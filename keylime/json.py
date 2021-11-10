"""
SPDX-License-Identifier: Apache-2.0
Copyright 2021 Sergio Correia (scorreia@redhat.com), Red Hat, Inc.
"""

# pylint: disable=import-self
import json


def __bytes_to_str(data):
    if isinstance(data, (bytes, bytearray)):
        return data.decode("utf-8")

    if isinstance(data, dict):
        for _k, _v in data.items():
            data[_k] = __bytes_to_str(_v)
        return data

    return data


def dumps(obj, **kwargs):
    try:
        ret = json.dumps(obj, **kwargs)
    except TypeError:
        # dumps() from the built-it json module does not work with bytes,
        # so let's convert those to str if we get a TypeError exception.
        ret = json.dumps(__bytes_to_str(obj), **kwargs)
    return ret


def dump(obj, fp, **kwargs):
    try:
        ret = json.dump(obj, fp, **kwargs)
    except TypeError:
        # dump() from the built-it json module does not work with bytes,
        # so let's convert those to str if we get a TypeError exception.
        ret = json.dump(obj, fp, **kwargs)
    return ret


def load(fp, **kwargs):
    return json.load(fp, **kwargs)


def loads(s, **kwargs):
    return json.loads(s, **kwargs)


# JSON pickler that fulfills SQLAlchemy requirements, from
# social-storage-sqlalchemy.
# https://github.com/python-social-auth/social-storage-sqlalchemy/commit/39d129
class JSONPickler:
    """JSON pickler wrapper around json lib since SQLAlchemy invokes
    dumps with extra positional parameters"""

    @classmethod
    def dumps(cls, value, *args, **kwargs):
        # pylint: disable=unused-argument
        """Dumps the python value into a JSON string"""
        return dumps(value)

    @classmethod
    def loads(cls, value):
        """Parses the JSON string and returns the corresponding python value"""
        return loads(value)
