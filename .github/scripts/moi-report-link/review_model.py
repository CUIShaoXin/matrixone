"""Resolve the currently available Kimi model without silently changing providers."""


def is_kimi_model(value):
    return isinstance(value, str) and value.startswith('kimi-k3')


def resolve_review_model(api):
    policy = api.data(api.request('/aistudio/model-policy'))
    models = policy.get('models')
    if not isinstance(models, list):
        raise ValueError('kimi_model_inventory_invalid')
    for candidate in ('kimi-k3.1-pro', 'kimi-k3'):
        if candidate in models:
            return candidate
    for candidate in sorted(models):
        if is_kimi_model(candidate):
            return candidate
    raise ValueError('kimi_model_unavailable')
