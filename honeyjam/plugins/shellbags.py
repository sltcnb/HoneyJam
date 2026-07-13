"""ShellBags - folder access / GUI navigation history (NTUSER + UsrClass)."""

from __future__ import annotations

from honeyjam.plugins._regipy_backed import RegipyBackedPlugin, _first


class _ShellBagBase(RegipyBackedPlugin):
    default_confidence = 45
    timestamp_keys = ("last_write", "modified", "slot_modified_date")

    def entry_title(self, entry: dict) -> str:
        return str(_first(entry, "path", "value", "name") or "(shellbag)")

    def entry_tags(self, entry: dict) -> list[str]:
        return ["file-access", "shellbags"]


class ShellBagsNtuserPlugin(_ShellBagBase):
    name = "shellbags_ntuser"
    description = "ShellBags folder-access history from NTUSER"
    hives = ["ntuser"]
    regipy_module = "regipy.plugins.ntuser.shellbags_ntuser"
    regipy_class = "ShellBagNtuserPlugin"


class ShellBagsUsrclassPlugin(_ShellBagBase):
    name = "shellbags_usrclass"
    description = "ShellBags folder-access history from UsrClass.dat"
    hives = ["usrclass"]
    regipy_module = "regipy.plugins.usrclass.shellbags_usrclass"
    regipy_class = "ShellBagUsrclassPlugin"
