"""Read-only, whitelist-shaped account and quota data from Antigravity desktop."""
import agy_desktop as desktop

UNKNOWN = 'unknown'


def value(mapping, key):
    """Return the actual field when present; do not turn absent/null into zero."""
    if not isinstance(mapping, dict):
        return UNKNOWN
    item = mapping.get(key, UNKNOWN)
    return UNKNOWN if item is None else item


def account_usage(backend_factory=desktop.Desktop):
    """Return only account identity, plan, and quota-window fields.

    The desktop RPC responses can contain login or profile implementation fields.
    This adapter deliberately does not return them.
    """
    backend = backend_factory()
    user_response = backend.rpc('GetUserStatus', {})
    quota_response = backend.rpc('RetrieveUserQuotaSummary', {})

    user = user_response.get('userStatus', {}) if isinstance(user_response, dict) else {}
    plan_status = value(user, 'planStatus')
    plan_info = plan_status.get('planInfo', {}) if isinstance(plan_status, dict) else {}
    response = quota_response.get('response', {}) if isinstance(quota_response, dict) else {}
    groups = value(response, 'groups')

    output_groups = UNKNOWN
    if isinstance(groups, list):
        output_groups = []
        for group in groups:
            buckets = value(group, 'buckets')
            output_buckets = UNKNOWN
            if isinstance(buckets, list):
                output_buckets = [
                    {
                        'bucketId': value(bucket, 'bucketId'),
                        'window': value(bucket, 'window'),
                        'remainingFraction': value(bucket, 'remainingFraction'),
                        'resetTime': value(bucket, 'resetTime'),
                    }
                    for bucket in buckets
                ]
            output_groups.append({
                'displayName': value(group, 'displayName'),
                'description': value(group, 'description'),
                'buckets': output_buckets,
            })

    return {
        'status': 'OK',
        'account': {
            'name': value(user, 'name'),
            'email': value(user, 'email'),
            'planName': value(plan_info, 'planName'),
        },
        'quota': {'groups': output_groups},
    }
