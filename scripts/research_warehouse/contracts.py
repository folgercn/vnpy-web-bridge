"""Audited, immutable v1 source contracts and registry pin."""

from .models import SourceEndpoint

FROZEN_REGISTRY_ID = "shfe-ine-public-daily-v1"
FROZEN_PUBLISHED_AT = "2026-07-29T00:00:00Z"
FROZEN_REGISTRY_RAW_SHA256 = (
    "638cb64fa8799b29b2f5ae915218d25f4cc15b6482555355661920c482e54dae"
)

FROZEN_SOURCES = (
    SourceEndpoint(
        source_id="shfe-daily-market-data-v1",
        exchange="SHFE",
        owner="Shanghai Futures Exchange",
        owner_reference_url="https://www.shfe.com.cn/",
        license_policy="OFFICIAL_PUBLIC_ENDPOINT_USE_TERMS_APPLY",
        use_terms_url=(
            "https://www.shfe.com.cn/reports/tradedata/dailyandweeklydata/"
        ),
        endpoint_template=(
            "https://www.shfe.com.cn/data/tradedata/future/"
            "dailydata/kx{yyyymmdd}.dat"
        ),
        documentation_url=(
            "https://www.shfe.com.cn/reports/tradedata/dailyandweeklydata/"
        ),
        allowed_hosts=("www.shfe.com.cn",),
        media_type="application/json",
        endpoint_schema_version="shfe-kx-dat-observed-2026-07-29-v1",
        availability_policy=(
            "POST_CLOSE_ONLY; HTTP absence is never calendar authority"
        ),
        required_top_level_fields=("o_curinstrument",),
        required_row_fields=(
            "DELIVERYMONTH",
            "PRODUCTID",
            "OPENPRICE",
            "HIGHESTPRICE",
            "LOWESTPRICE",
            "CLOSEPRICE",
            "SETTLEMENTPRICE",
            "VOLUME",
            "OPENINTEREST",
        ),
    ),
    SourceEndpoint(
        source_id="ine-daily-market-data-v1",
        exchange="INE",
        owner="Shanghai International Energy Exchange",
        owner_reference_url="https://www.ine.cn/",
        license_policy="OFFICIAL_PUBLIC_ENDPOINT_USE_TERMS_APPLY",
        use_terms_url=(
            "https://www.ine.cn/reports/tradedata/dailyandweeklydata/"
        ),
        endpoint_template=(
            "https://www.ine.cn/data/tradedata/future/"
            "dailydata/kx{yyyymmdd}.dat"
        ),
        documentation_url=(
            "https://www.ine.cn/reports/tradedata/dailyandweeklydata/"
        ),
        allowed_hosts=("www.ine.cn",),
        media_type="application/json",
        endpoint_schema_version="ine-kx-dat-observed-2026-07-29-v1",
        availability_policy=(
            "POST_CLOSE_ONLY; HTTP absence is never calendar authority"
        ),
        required_top_level_fields=("o_curinstrument",),
        required_row_fields=(
            "DELIVERYMONTH",
            "PRODUCTID",
            "OPENPRICE",
            "HIGHESTPRICE",
            "LOWESTPRICE",
            "CLOSEPRICE",
            "SETTLEMENTPRICE",
            "VOLUME",
            "OPENINTEREST",
        ),
    ),
)
