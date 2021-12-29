import os


class Config(object):
    SRC_CLUSTER_IP = os.environ.get("SRC_CLUSTER_IP", None)
    SRC_ACCOUNT = os.environ.get("SRC_ACCOUNT", "cloud_admin")
    SRC_PROJECT_ID = os.environ.get("SRC_PROJECT_ID", "default")
    SRC_USERNAME = os.environ.get("SRC_USERNAME", "admin")
    SRC_PASSWORD = os.environ.get("SRC_PASSWORD", None)
    SRC_MFA_SECRET = os.environ.get("SRC_MFA_SECRET", None)

    DST_CLUSTER_IP = os.environ.get("DST_CLUSTER_IP", None)
    DST_ACCOUNT = os.environ.get("DST_ACCOUNT", "cloud_admin")
    DST_PROJECT_ID = os.environ.get("DST_PROJECT_ID", "default")
    DST_USERNAME = os.environ.get("DST_USERNAME", "admin")
    DST_PASSWORD = os.environ.get("DST_PASSWORD", "admin")
    DST_MFA_SECRET = os.environ.get("DST_MFA_SECRET", None)
    DST_CC_CLOUD_ID = os.environ.get("DST_CC_CLOUD_ID", None)
    DST_CC_VPSA_ID = os.environ.get("DST_CC_VPSA_ID", None)
    DST_CC_HOST = os.environ.get("DST_CC_HOST", None)
    DST_CC_URL_PREFIX_TEMPLATE = os.environ.get("DST_CC_URL_PREFIX_TEMPLATE",
                                                "https://{host}:8888/clouds/{cloud}/vpsas/{vsa}/pt")
    DST_VPSA_VERIFY_SSL = os.environ.get("DST_VPSA_VERIFY_SSL", False)
    SRC_TRANSFER_PROJECT_ID = os.environ.get("SRC_TRANSFER_PROJECT_ID", SRC_PROJECT_ID)
    DST_TRANSFER_PROJECT_ID = os.environ.get("DST_TRANSFER_PROJECT_ID", DST_PROJECT_ID)
    DST_POOL_ID = os.environ.get("DST_POOL_ID", None)

    DEFAULT_IS_DRY_RUN = True
