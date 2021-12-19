import os


class Config(object):
    SRC_CLUSTER_IP = os.environ.get("SRC_CLUSTER_IP", None)
    SRC_ACCOUNT = os.environ.get("SRC_ACCOUNT", None)
    SRC_USERNAME = os.environ.get("SRC_USERNAME", None)
    SRC_PASSWORD = os.environ.get("SRC_PASSWORD", None)
    SRC_PROJECT = os.environ.get("SRC_PROJECT", None)
    SRC_MFA_SECRET = os.environ.get("SRC_MFA_SECRET", None)

    DST_CLUSTER_IP = os.environ.get("DST_CLUSTER_IP", None)
    DST_ACCOUNT = os.environ.get("DST_ACCOUNT", None)
    DST_USERNAME = os.environ.get("DST_USERNAME", None)
    DST_PASSWORD = os.environ.get("DST_PASSWORD", None)
    DST_PROJECT = os.environ.get("DST_PROJECT", None)
    DST_MFA_SECRET = os.environ.get("DST_MFA_SECRET", None)

    DST_POOL_ID = os.environ.get("DST_POOL_ID", None)

    DEFAULT_IS_DRY_RUN = True
