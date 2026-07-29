import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType

from astrbot.core.star.filter.command import CommandFilter
from astrbot.core.star.filter.command_group import CommandGroupFilter
from astrbot.core.star.star_handler import star_handlers_registry


class CommandGroupRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package_name = "astrbot_plugin_pixiv_reborn_command_group_test"
        cls.existing_handlers = set(star_handlers_registry.star_handlers_map)

        root = Path(__file__).resolve().parents[1]
        package = ModuleType(cls.package_name)
        package.__path__ = [str(root)]
        sys.modules[cls.package_name] = package

        module_name = f"{cls.package_name}.main"
        spec = importlib.util.spec_from_file_location(module_name, root / "main.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        cls.plugin_handlers = [
            handler
            for handler in star_handlers_registry
            if handler.handler_module_path.startswith(cls.package_name)
        ]

    @classmethod
    def tearDownClass(cls):
        for handler in list(star_handlers_registry):
            if handler.handler_full_name not in cls.existing_handlers:
                star_handlers_registry.remove(handler)
        for module_name in list(sys.modules):
            if module_name == cls.package_name or module_name.startswith(
                f"{cls.package_name}."
            ):
                del sys.modules[module_name]

    def test_registers_one_top_level_pixiv_group(self):
        root_groups = [
            event_filter
            for handler in self.plugin_handlers
            for event_filter in handler.event_filters
            if isinstance(event_filter, CommandGroupFilter)
            and event_filter.parent_group is None
        ]

        self.assertEqual(len(root_groups), 1)
        self.assertEqual(root_groups[0].group_name, "pixiv")

    def test_command_tree_matches_documented_groups(self):
        root_group = next(
            event_filter
            for handler in self.plugin_handlers
            for event_filter in handler.event_filters
            if isinstance(event_filter, CommandGroupFilter)
            and event_filter.parent_group is None
        )
        direct_commands = {
            child.command_name
            for child in root_group.sub_command_filters
            if isinstance(child, CommandFilter)
        }
        subgroups = {
            child.group_name: {
                command.command_name
                for command in child.sub_command_filters
                if isinstance(command, CommandFilter)
            }
            for child in root_group.sub_command_filters
            if isinstance(child, CommandGroupFilter)
        }

        self.assertEqual(
            direct_commands,
            {"search", "deep", "and", "hot", "help", "ai", "config"},
        )
        self.assertEqual(
            subgroups,
            {
                "illust": {
                    "new",
                    "recommended",
                    "get",
                    "ranking",
                    "related",
                    "comments",
                    "showcase",
                    "trending",
                },
                "user": {"search", "detail", "works"},
                "novel": {
                    "search",
                    "recommended",
                    "new",
                    "series",
                    "comments",
                    "download",
                },
                "subscribe": {"add", "remove", "list"},
                "random": {
                    "add",
                    "del",
                    "list",
                    "suspend",
                    "resume",
                    "status",
                    "force",
                    "ranking-add",
                    "ranking-del",
                    "ranking-list",
                },
                "fanbox": {
                    "creator",
                    "post",
                    "recommended",
                    "artist",
                    "download",
                    "status",
                    "stop",
                    "view",
                },
            },
        )
        self.assertEqual(
            len(direct_commands)
            + sum(len(commands) for commands in subgroups.values()),
            45,
        )

    def test_does_not_register_legacy_top_level_commands(self):
        top_level_commands = [
            event_filter.command_name
            for handler in self.plugin_handlers
            for event_filter in handler.event_filters
            if isinstance(event_filter, CommandFilter)
            and event_filter.parent_command_names == [""]
        ]

        self.assertEqual(top_level_commands, [])


if __name__ == "__main__":
    unittest.main()
