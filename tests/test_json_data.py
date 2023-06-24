import json
import unittest

import typer
from asdfuzz.http.json_data import Node, NodeType, _nodes_to_object, NodeKey, JSONData
from parameterized import parameterized

objects_and_json_nodes = [
    (
        '{"1": {"2": 3}, "4": 5, "6": [7, {"8": 9, "10": 11}]}',
        [
            Node(keys=[NodeKey(NodeType.DICT, '1'), NodeKey(NodeType.DICT, '2'), NodeKey(NodeType.VALUE, 3)]),
            Node(keys=[NodeKey(NodeType.DICT, '4'), NodeKey(NodeType.VALUE, 5)]),
            Node(keys=[NodeKey(NodeType.DICT, '6'), NodeKey(NodeType.LIST, 0), NodeKey(NodeType.VALUE, 7)]),
            Node(keys=[NodeKey(NodeType.DICT, '6'), NodeKey(NodeType.LIST, 1), NodeKey(NodeType.DICT, '8'),
                       NodeKey(NodeType.VALUE, 9)]),
            Node(keys=[NodeKey(NodeType.DICT, '6'), NodeKey(NodeType.LIST, 1), NodeKey(NodeType.DICT, '10'),
                       NodeKey(NodeType.VALUE, 11)]),
        ]
    ),
    (
        '{}',
        [Node(keys=[NodeKey(NodeType.VALUE, {})])]
    ),
    (
        '[]',
        [Node(keys=[NodeKey(NodeType.VALUE, [])])]
    ),
    (
        '"asd"',
        [Node(keys=[NodeKey(NodeType.VALUE, "asd")])]
    ),
]


class TestJSONNode(unittest.TestCase):
    @parameterized.expand(objects_and_json_nodes)
    def test_to_json_node(
            self,
            json_object,
            expected_json_nodes
    ):
        self.assertEqual(
            expected_json_nodes,
            Node.from_object(json.loads(json_object))
        )

    @parameterized.expand(objects_and_json_nodes)
    def test_nodes_to_object(
            self,
            expected_json_object,
            json_nodes,
    ):
        self.assertEqual(
            expected_json_object,
            _nodes_to_object(json_nodes)
        )

    def test_print_node(self):
        node = Node(keys=[NodeKey(NodeType.DICT, '6'), NodeKey(NodeType.LIST, 1), NodeKey(NodeType.DICT, '8'),
                          NodeKey(NodeType.VALUE, 9)])
        self.assertEqual(
            '6.[1].8=9',
            typer.unstyle(str(node))
        )


class TestJSONData(unittest.TestCase):
    @parameterized.expand(objects_and_json_nodes)
    def test_json_data_from_json(
            self,
            json_object,
            json_nodes
    ):
        json_data = JSONData(json_object)
        self.assertEqual(
            json_nodes,
            json_data.json_nodes,
        )

    @parameterized.expand(objects_and_json_nodes)
    def test_json_data_from_and_to_json(
            self,
            json_object,
            _
    ):
        json_string = JSONData(json_object).to_json()
        self.assertEqual(
            json_object,
            json_string,
        )

    def test_json_data_modified(self):
        json_input = '{"1": {"2": 3}, "4": 5, "6": [7, {"8": 9, "10": 11}]}'
        expected_result = '{"1": {"2": 3}, "4": 5, "6": [7, {"8": "modified", "10": 11}]}'
        json_data = JSONData(json_input)
        json_data.json_nodes[3].keys[-1].key = "modified"

        self.assertEqual(
            expected_result,
            json_data.to_json()
        )
