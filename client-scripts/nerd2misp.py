#!/usr/bin/env python3
"""
Synchronize a MISP event with the most active malicious IPs from NERD.

Queries NERD's API (search/ip endpoint) for IPs in the configured threat
categories (by default 'scan' and 'login') with confidence strictly greater
than a configured threshold, and syncs them as ip-src attributes of a single
MISP event: attributes for IPs that are no longer active are removed,
attributes for newly active IPs are added.
"""

import argparse
import ipaddress
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import NamedTuple, Optional

import requests
import yaml
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPEventReport
from requests.adapters import HTTPAdapter

LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
logger = logging.getLogger("nerd2misp")

NERD_API_TIMEOUT = 300  # default per-request timeout for NERD API calls
MISP_TIMEOUT = 120  # per-request timeout for calls to the MISP API
DEFAULT_MAX_WORKERS = 10  # concurrent requests to MISP
DEFAULT_BATCH_SIZE = 100  # new attributes added per bulk add_attribute() call


class MISPRequestError(Exception):
    pass


class NERDAPIError(Exception):
    pass


def check(result, what):
    """
    Raise MISPRequestError if `result` (return value of a PyMISP call) reports
    an error, otherwise return it unchanged. PyMISP signals most failures by
    returning {'errors': ...} instead of raising, so without this they'd pass
    silently.
    """
    if isinstance(result, dict) and result.get('errors'):
        raise MISPRequestError(f"{what} failed: {result['errors']}")
    return result


# Confidence is reported in buckets rather than as the raw value
CONFIDENCE_BUCKETS = [
    (0.75, 'very high'),
    (0.5, 'high'),
    (float('-inf'), 'medium'),  # only reachable with confidence_threshold < 0.5
]

# The search/ip API filters confidence with ">=", while confidence_threshold
# and the bucket boundaries above mean strictly ">", so this is added to each
# of them when querying (e.g. 0.5 -> 0.5001).
API_CONFIDENCE_EPSILON = 0.0001


def api_min_confidence(threshold):
    return round(threshold + API_CONFIDENCE_EPSILON, 6)


def nerd_search_ips(session, nerd_cfg, category, min_confidence):
    """
    Return the set of IPs NERD has in threat `category` with confidence
    >= `min_confidence`, using the search/ip API endpoint with list output
    (just the IPs, one per line).
    """
    url = nerd_cfg['api_url'].rstrip('/') + '/search/ip/'
    params = {
        'tc_category': category,
        'tc_confidence': min_confidence,
        'o': 'list',
        'sortby': 'none', 
    }
    what = f"NERD search/ip (category {category!r}, confidence >= {min_confidence})"
    resp = session.get(url, params=params, timeout=nerd_cfg.get('timeout', NERD_API_TIMEOUT))
    if resp.status_code != 200:
        # NERD API errors are JSON: {"err_n": <HTTP code>, "error": "<message>"}
        try:
            message = resp.json()['error']
        except (ValueError, KeyError, TypeError):
            message = resp.text[:200]
        raise NERDAPIError(f"{what} failed with HTTP {resp.status_code}: {message}")

    ips = set()
    for line in resp.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            # Not the expected list of IPs
            raise NERDAPIError(f"{what}: unexpected response, not an IP address: {line[:100]!r}") from None
        ips.add(line)
    logger.debug(f"{what}: {len(ips)} IPs")
    return ips


def load_nerd_ips(nerd_cfg, categories, confidence_threshold):
    """
    Query NERD for IPs in any of `categories` with confidence strictly greater
    than `confidence_threshold`. Returns {ip: {category: bucket label, ...}, ...}
    (see CONFIDENCE_BUCKETS).

    The list output of search/ip gives just the IPs, not their confidence, so
    the bucket is found by querying once more per bucket boundary above the
    threshold: e.g. an IP that is also returned by the query for > 0.75 is
    'very high', otherwise 'high'.
    """
    # Bucket of IPs just above the threshold, and the higher bucket boundaries in ascending order
    base_label = next(label for lower, label in CONFIDENCE_BUCKETS if lower <= confidence_threshold)
    boundaries = [(lower, label) for lower, label in reversed(CONFIDENCE_BUCKETS) if lower > confidence_threshold]

    session = requests.Session()
    session.headers['Authorization'] = f"token {nerd_cfg['api_key']}"
    session.verify = nerd_cfg.get('verify_cert', True)

    result = {}
    for category in sorted(categories):
        for ip in nerd_search_ips(session, nerd_cfg, category, api_min_confidence(confidence_threshold)):
            result.setdefault(ip, {})[category] = base_label
        for lower, label in boundaries:
            for ip in nerd_search_ips(session, nerd_cfg, category, api_min_confidence(lower)):
                if category in result.get(ip, {}):  # skip IPs that only crossed the threshold between the queries
                    result[ip][category] = label
    return result


def describe_buckets(confidence_threshold):
    """Human-readable description of the buckets reachable with the given threshold,
    e.g. '**high** (0.5-0.75) or **very high** (above 0.75)'."""
    parts = []
    upper = None
    for lower, label in CONFIDENCE_BUCKETS:
        if upper is not None and upper <= confidence_threshold:
            break
        lower = max(lower, confidence_threshold)
        parts.append(f"**{label}** ({f'above {lower}' if upper is None else f'{lower}-{upper}'})")
        upper = lower
    parts.reverse()
    return parts[0] if len(parts) == 1 else f"{', '.join(parts[:-1])} or {parts[-1]}"


def format_comment(categories):
    """e.g. {'login': 'high', 'scan': 'very high'} -> 'scan: very high, login: high'.
    Category itself is conveyed by the attribute's tags, this is just for the
    confidence. Ordered by bucket (highest first), then by name."""
    rank = {label: i for i, (_, label) in enumerate(CONFIDENCE_BUCKETS)}
    ordered = sorted(categories.items(), key=lambda cat_label: (rank[cat_label[1]], cat_label[0]))
    return ", ".join(f"{cat}: {label}" for cat, label in ordered)


# Maps NERD threat categories to MISP RSIT (Reference Security Incident
# Taxonomy) tags. Categories without an entry here fall back to a
# 'nerd:category="..."' tag.
CATEGORY_TAGS = {
    'scan': 'rsit:information-gathering="scanner"',
    'login': 'rsit:intrusion-attempts="brute-force"',
}


def category_tag(category):
    return CATEGORY_TAGS.get(category, f'nerd:category="{category}"')


def category_tags(categories):
    return {category_tag(cat) for cat in categories}


def get_or_create_event(misp, event_info, event_tags, distribution, threat_level_id, analysis, dry_run=False):
    """
    Fetch the existing MISP event to sync (identified by its exact info/title),
    or create a new one if it doesn't exist yet. In dry-run mode, a
    not-yet-existing event is only built locally (not sent to MISP).
    """
    # metadata=True: just find the event here, its attributes are fetched once by get_event() below
    found = check(misp.search(eventinfo=event_info, metadata=True, pythonify=True), "Searching for the event")
    matches = sorted((e for e in found if e.info == event_info), key=lambda e: int(e.id))
    if matches:
        if len(matches) > 1:
            logger.warning(f"Found {len(matches)} events titled {event_info!r}, using the oldest one (ID {matches[0].id})")
        logger.debug(f"Using existing event (ID {matches[0].id})")
        return check(misp.get_event(matches[0].uuid, pythonify=True), "Fetching the event")

    event = MISPEvent()
    event.info = event_info
    event.date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    event.distribution = distribution
    event.threat_level_id = threat_level_id
    event.analysis = analysis
    for tag in event_tags:
        event.add_tag(tag)

    if dry_run:
        logger.info("[dry-run] No matching event found, would create a new one")
        return event

    new_event = check(misp.add_event(event, pythonify=True), "Creating the event")
    logger.info(f"Created new event (ID {new_event.id})")
    return new_event


def apply_tag(misp, entity, tag):
    """Add `tag` to `entity` (an event, attribute, or their UUID)."""
    result = misp.tag(entity, tag)
    if isinstance(result, dict) and 'errors' in result:
        logger.warning(f"Could not add tag {tag!r}: {result['errors']}")
        return False
    return True


def remove_tag(misp, entity, tag):
    """Same as apply_tag(), but for removing a tag."""
    result = misp.untag(entity, tag)
    if isinstance(result, dict) and 'errors' in result:
        logger.warning(f"Could not remove tag {tag!r}: {result['errors']}")
        return False
    return True


def ensure_event_tags(misp, event, wanted_tags, dry_run=False):
    """Add any of `wanted_tags` not already present on the event. Never removes any
    (the event may carry other, unrelated tags added by an analyst).
    Returns (changed, tag_failures)."""
    current = {t.name for t in event.tags} if event.tags else set()
    missing = wanted_tags - current
    if not missing:
        return False, 0
    if dry_run:
        logger.info(f"[dry-run] Would add event tag(s): {sorted(missing)}")
        return True, 0
    failures = sum(not apply_tag(misp, event, tag) for tag in missing)
    logger.debug(f"Added event tag(s): {sorted(missing)}")
    return True, failures


# Title used to (re-)identify the event's own Event Report across runs (matched by
# name, analogous to how event_info identifies the event itself).
REPORT_NAME = "About this event (nerd2misp)"


def build_description(categories, confidence_threshold):
    return (
        f"# {REPORT_NAME}\n\n"
        f"This event lists IP addresses reported by NERD as active in the following "
        f"categories: **{', '.join(sorted(categories))}**, restricted to high-confidence "
        f"data only (confidence > {confidence_threshold}).\n\n"
        f"NERD's confidence score (0-1, shown per category in each attribute's comment "
        f"as {describe_buckets(confidence_threshold)}) "
        f"reflects how much independent, recent evidence supports that classification: "
        f"it's derived from the number of reports and distinct reporting sources seen "
        f"over the last 14 days, weighted so that more recent activity counts more - it "
        f"is a measure of how well-evidenced the classification is, **not a severity/risk "
        f"rating**.\n\n"
        f"The attribute list is continuously updated by an automated script to reflect "
        f"NERD's current data - IP addresses are added and removed on each sync. Please "
        f"don't edit the ip-src attributes of this event manually, changes will be "
        f"overwritten."
    )


def ensure_event_report(misp, event, name, content, dry_run=False):
    """
    Ensure a single Event Report titled `name` is present on the event and its
    content is up to date: added if missing, refreshed if the content changed
    (e.g. the configured categories/threshold changed).
    Returns (changed, failed).
    """
    existing = None
    if getattr(event, "id", None) is not None:  # otherwise a not-yet-created event in dry-run mode
        try:
            reports = check(misp.get_event_reports(event.id, pythonify=True), "Listing event reports")
        except MISPRequestError as e:
            logger.warning(str(e))
            return False, True
        existing = next((r for r in reports if r.name == name), None)

    if existing and existing.content == content:
        return False, False
    action = 'update' if existing else 'add'

    if dry_run:
        logger.info(f"[dry-run] Would {action} event report {name!r}")
        return True, False

    if existing:
        existing.content = content
        result = misp.update_event_report(existing)
    else:
        report = MISPEventReport()
        report.name = name
        report.content = content
        report.distribution = 5  # "Inherit event" -- follow the parent event's own distribution
        result = misp.add_event_report(event.id, report)

    try:
        check(result, f"Trying to {action} event report {name!r}")
    except MISPRequestError as e:
        logger.warning(str(e))
        return False, True
    logger.debug(f"Event report {action}d")
    return True, False


class AttributeUpdate(NamedTuple):
    attr: MISPAttribute
    new_comment: Optional[str]  # None if the comment doesn't need to change
    tags_to_add: set
    tags_to_remove: set


class SyncPlan(NamedTuple):
    to_add: list  # [(ip, {category: bucket label}), ...]
    to_update: list  # [AttributeUpdate, ...]
    to_delete: list  # [MISPAttribute, ...]


def compute_sync_plan(event, wanted_ips, managed_tags):
    """
    Compare ip-src attributes of `event` with `wanted_ips` (ip -> {category: bucket label})
    and work out what needs to change: new IPs to add, existing attributes whose
    comment/category tags no longer match, and attributes of IPs that are no
    longer active.

    `managed_tags` is the set of all category tags this script may add/remove
    (i.e. category_tag(cat) for every configured category) -- since RSIT tags
    are a shared namespace an analyst might also use directly on the same
    attribute for unrelated reasons, only tags in this set are ever removed,
    never an arbitrary/unrecognized one.
    """
    existing_attrs = {attr.value: attr for attr in event.attributes if attr.type == "ip-src"}
    to_add = []
    to_update = []
    for ip, categories in wanted_ips.items():
        attr = existing_attrs.get(ip)
        if attr is None:
            to_add.append((ip, categories))
            continue
        comment = format_comment(categories)
        wanted_tags = category_tags(categories)
        current_tags = {t.name for t in attr.tags} if attr.tags else set()
        update = AttributeUpdate(
            attr=attr,
            new_comment=comment if attr.comment != comment else None,
            tags_to_add=wanted_tags - current_tags,
            tags_to_remove=(current_tags - wanted_tags) & managed_tags,
        )
        if update.new_comment is not None or update.tags_to_add or update.tags_to_remove:
            to_update.append(update)
    to_delete = [attr for ip, attr in existing_attrs.items() if ip not in wanted_ips]
    return SyncPlan(to_add, to_update, to_delete)


def log_sync_plan(plan):
    """Dry-run report of what sync_event() would do (per-IP details only with -v)."""
    logger.info(f"[dry-run] Would add {len(plan.to_add)}, update {len(plan.to_update)}, "
                f"remove {len(plan.to_delete)} attribute(s)")
    for ip, categories in plan.to_add:
        logger.debug(f"[dry-run]   + {ip} ({format_comment(categories)})")
    for upd in plan.to_update:
        changes = []
        if upd.new_comment is not None:
            changes.append(f"comment {upd.attr.comment!r} -> {upd.new_comment!r}")
        if upd.tags_to_add:
            changes.append(f"add tags {sorted(upd.tags_to_add)}")
        if upd.tags_to_remove:
            changes.append(f"remove tags {sorted(upd.tags_to_remove)}")
        logger.debug(f"[dry-run]   ~ {upd.attr.value}: {'; '.join(changes)}")
    for attr in plan.to_delete:
        logger.debug(f"[dry-run]   - {attr.value}")


def _apply_attribute_update(misp, update):
    """
    Apply one AttributeUpdate. Runs inside a worker thread -- see sync_event().
    Raises MISPRequestError if the comment update fails; returns the number of
    failed tag operations.
    """
    attr = update.attr
    if update.new_comment is not None:
        attr.comment = update.new_comment
        check(misp.update_attribute(attr), f"Updating attribute {attr.value}")
    failures = sum(not apply_tag(misp, attr.uuid, tag) for tag in update.tags_to_add)
    failures += sum(not remove_tag(misp, attr.uuid, tag) for tag in update.tags_to_remove)
    return failures


def _delete_attribute(misp, attr):
    check(misp.delete_attribute(attr.uuid), f"Deleting attribute {attr.value}")


def _chunked(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _add_attribute_batch(misp, event_id, batch, to_ids):
    """
    Bulk-create a batch of new ip-src attributes, including their category
    tags, in a single API call (MISP 2.4.113+): far fewer round-trips than
    adding (and tagging) them one at a time.

    Returns the number of attributes created. If some values in the batch fail
    (e.g. a duplicate), they're logged and simply left out; they'll be picked
    up as an update on a later run once they show up as an existing
    attribute. Likewise, if MISP can't attach a tag (e.g. the taxonomy isn't
    enabled), the attribute is still created and the tag is retried as an
    update on the next run.
    """
    attrs = []
    for ip, categories in batch:
        attr = MISPAttribute()
        attr.type = "ip-src"
        attr.value = ip
        attr.comment = format_comment(categories)
        attr.to_ids = to_ids
        for tag in sorted(category_tags(categories)):
            attr.add_tag(tag)
        attrs.append(attr)

    # Raw response on purpose: PyMISP's pythonify=True crashes on a bulk add
    # where only some of the attributes fail.
    result = misp.add_attribute(event_id, attrs)
    created = result.get('Attribute', []) if isinstance(result, dict) else []
    if isinstance(created, dict):  # a single created attribute comes as a dict, not a list
        created = [created]
    if not created:
        check(result, f"Adding a batch of {len(batch)} attributes")
        raise MISPRequestError(f"Adding a batch of {len(batch)} attributes: unexpected response: {result}")
    if result.get('errors'):
        logger.warning(f"{len(batch) - len(created)} of {len(batch)} attributes in a batch failed to add: {result['errors']}")
    return len(created)


def sync_event(misp, event, plan, to_ids, max_workers=DEFAULT_MAX_WORKERS, batch_size=DEFAULT_BATCH_SIZE):
    """
    Apply a SyncPlan (see compute_sync_plan()) to `event`.
    Returns (changed, tag_failures).

    New attributes are created in batches of `batch_size` (one API call each,
    see _add_attribute_batch()); everything else (updates, tag changes,
    deletes) is one API call per operation, since MISP/PyMISP has no bulk
    update/delete. All of it is spread across `max_workers` threads, since
    running tens of thousands of calls one at a time is far too slow.
    """
    added = updated = removed = tag_failures = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        add_futures = [pool.submit(_add_attribute_batch, misp, event.id, batch, to_ids)
                       for batch in _chunked(plan.to_add, batch_size)]
        update_futures = {pool.submit(_apply_attribute_update, misp, upd): upd.attr.value for upd in plan.to_update}
        delete_futures = {pool.submit(_delete_attribute, misp, attr): attr.value for attr in plan.to_delete}

        for future in as_completed(add_futures):
            try:
                added += future.result()
            except Exception:
                logger.exception("Failed to add a batch of attributes")
        for future in as_completed(update_futures):
            try:
                tag_failures += future.result()
                updated += 1
            except Exception:
                logger.exception(f"Failed to update attribute {update_futures[future]}")
        for future in as_completed(delete_futures):
            try:
                future.result()
                removed += 1
            except Exception:
                logger.exception(f"Failed to delete attribute {delete_futures[future]}")

    logger.info(f"Attributes: {added} added, {updated} updated, {removed} removed")
    if tag_failures:
        logger.warning(f"{tag_failures} tag operation(s) failed (see warnings above) - "
                        f"is the relevant taxonomy enabled on this MISP instance?")
    return bool(added or updated or removed), tag_failures


def main():
    parser = argparse.ArgumentParser(
        prog="nerd2misp.py",
        description="Synchronize a MISP event with the most active malicious IPs from NERD (scan/login categories)."
    )
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default='/etc/nerd/nerd2misp.yml',
                         help='Path to configuration file (default: /etc/nerd/nerd2misp.yml)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    parser.add_argument('-n', '--dry-run', action='store_true',
                         help="Download/parse data and show what would change, but don't modify MISP "
                              "(use with -v to list individual IPs)")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel('DEBUG')

    logger.info(f"Loading config file {args.config}")
    try:
        with open(args.config) as f:
            config = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        logger.error(f"Cannot read config file: {e}")
        sys.exit(1)
    if not isinstance(config, dict):
        logger.error(f"Config file {args.config} is empty or not a YAML mapping")
        sys.exit(1)

    nerd_cfg = config.get('nerd') or {}
    misp_cfg = config.get('misp') or {}
    categories = set(nerd_cfg.get('categories', ['scan', 'login']))
    confidence_threshold = float(nerd_cfg.get('confidence_threshold', 0.5))

    if not nerd_cfg.get('api_url') or not nerd_cfg.get('api_key'):
        logger.error("Missing 'nerd.api_url' / 'nerd.api_key' in configuration file")
        sys.exit(1)

    try:
        wanted_ips = load_nerd_ips(nerd_cfg, categories, confidence_threshold)
    except (NERDAPIError, requests.RequestException) as e:
        logger.error(f"Cannot get NERD data: {e}")
        sys.exit(1)
    logger.info(f"{len(wanted_ips)} IPs match categories {sorted(categories)} with confidence > {confidence_threshold}")

    if not wanted_ips:
        # Don't touch MISP on empty results - much more likely a data/parsing problem
        # than "there are really no active IPs right now", so don't wipe the event.
        logger.warning("No IPs matched, exiting without modifying MISP")
        sys.exit(1)

    try:
        misp_url = misp_cfg['url']
        misp_key = misp_cfg['key']
    except KeyError:
        logger.error("Missing 'misp.url' / 'misp.key' in configuration file")
        sys.exit(1)

    event_info = misp_cfg.get('event_info', "[NERD] Most active malicious IPs (scans, login attempts)")
    event_tags = misp_cfg.get('event_tags', [])
    max_workers = int(misp_cfg.get('max_workers', DEFAULT_MAX_WORKERS))
    batch_size = int(misp_cfg.get('batch_size', DEFAULT_BATCH_SIZE))

    try:
        # Size the connection pool to match max_workers, otherwise requests beyond the
        # (small) default pool size would just queue up behind each other anyway.
        adapter = HTTPAdapter(pool_connections=max_workers, pool_maxsize=max_workers)
        misp = PyMISP(misp_url, misp_key, misp_cfg.get('verify_cert', True), timeout=MISP_TIMEOUT, https_adapter=adapter)
    except Exception as e:
        logger.error(f"Cannot connect to MISP at {misp_url}: {e}")
        sys.exit(1)

    try:
        event = get_or_create_event(
            misp, event_info, event_tags,
            distribution=misp_cfg.get('distribution', 0),
            threat_level_id=misp_cfg.get('threat_level_id', 2),
            analysis=misp_cfg.get('analysis', 2),
            dry_run=args.dry_run,
        )
    except Exception as e:
        logger.error(f"Cannot get or create the MISP event: {e}")
        sys.exit(1)

    managed_tags = category_tags(categories)
    _, event_tag_failures = ensure_event_tags(misp, event, set(event_tags) | managed_tags, dry_run=args.dry_run)
    _, report_failed = ensure_event_report(misp, event, REPORT_NAME, build_description(categories, confidence_threshold), dry_run=args.dry_run)

    plan = compute_sync_plan(event, wanted_ips, managed_tags)

    if args.dry_run:
        log_sync_plan(plan)
        logger.info("[dry-run] Not modifying MISP.")
        return

    try:
        changed, attr_tag_failures = sync_event(misp, event, plan, to_ids=misp_cfg.get('to_ids', True),
                                                 max_workers=max_workers, batch_size=batch_size)
    except Exception as e:
        logger.error(f"Failed to sync attributes: {e}")
        sys.exit(1)

    tag_failures = event_tag_failures + attr_tag_failures + report_failed

    if not changed:
        logger.info("No changes, nothing to publish")
        sys.exit(2 if tag_failures else 0)

    try:
        check(misp.publish(event.id, alert=False), "Publishing the event")
    except Exception as e:
        # Attribute changes above are already committed individually, only publishing failed
        logger.error(f"Attributes synced, but failed to publish the event: {e}")
        sys.exit(1)
    logger.info("Event synced and published")
    if tag_failures:
        sys.exit(2)


if __name__ == '__main__':
    main()
