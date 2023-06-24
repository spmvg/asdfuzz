import json
from dataclasses import dataclass, astuple
from enum import Enum, auto
from typing import List, Any, Union, Dict

import typer


class NodeType(Enum):
    """
    The key type of the node can represent either further nested structure (``dict`` or ``list``) or a leaf
    (any JSON compatible value).
    """
    DICT = auto()
    """ Indicates that this key contains further nested structure: specifically, a ``dict``. """
    LIST = auto()
    """ Indicates that this key contains further nested structure: specifically, a ``list``. """
    VALUE = auto()
    """ Indicates that this key contains a leaf. The type can be any JSON compatible value. """


@dataclass
class NodeKey:
    """ Absolute key of a value in the JSON structure. """
    key_type: NodeType
    """
    The key type ``key_type`` of the node can represent either further nested structure (``dict`` or ``list``) or a leaf
    (any JSON compatible value).
    """
    key: Any
    """ Value of the JSON at this key. The type can be any JSON compatible value. """

    def __iter__(self):
        return iter(astuple(self))


@dataclass
class Node:
    """ A single level in the nested JSON data. """
    keys: List[NodeKey]
    """ Absolute keys of the JSON data in this level. """
    fuzz = True
    """ Whether to fuzz the keys in this JSON node. """

    @classmethod
    def from_object(cls, json_object: Any) -> List['Node']:
        """
        Given an object representing JSON data (the output of ``json.loads``, e.g. a ``dict`` or ``list`` of any
        structure), return the ``Node`` objects representing the JSON data at this level.
        Since the outer level of JSON data can be a ``list``, the return type is a list of ``Node`` objects, not a
        single ``Node``.
        """
        worklist = []
        _flatten_nested_list(
            _nested_list_of_json_nodes(json_object, Node([])),
            worklist
        )
        return worklist

    def __str__(self):
        """ Printable and colorized representation of this ``Node``. """
        string = ""
        for loop_index, key in enumerate(self.keys[:-1]):
            if loop_index != 0:
                string += '.'
            if key.key_type == NodeType.LIST:
                string += f'[{key.key}]'
                continue
            string += f'{key.key}'
        string += '=' + typer.style(
            f'{self.keys[-1].key}',
            bg=typer.colors.RED
        )
        return string


def _nested_list_of_json_nodes(
        json_object: Any,
        parent_keys: 'Node',
) -> List[Union['Node', List]]:
    """ Recursively discover all ``Node`` objects in the JSON. """
    existing_keys = parent_keys.keys

    if isinstance(json_object, dict) and json_object:
        return [
                _nested_list_of_json_nodes(value, Node(existing_keys + [NodeKey(NodeType.DICT, key)]))
                for key, value in json_object.items()
        ]
    elif isinstance(json_object, list) and json_object:
        return [
            _nested_list_of_json_nodes(value, Node(existing_keys + [NodeKey(NodeType.LIST, key)]))
            for key, value in enumerate(json_object)
        ]
    return [
        Node(existing_keys + [NodeKey(NodeType.VALUE, json_object)])
    ]


def _flatten_nested_list(
        nested_list: Union['Node', List],
        work_list: List[Union['Node', List]],
) -> None:
    """
    Iteratively flattens the nested_list and puts it in the work_list.
    """
    if isinstance(nested_list, Node):
        work_list.append(nested_list)
        return
    elif isinstance(nested_list, list):
        for item in nested_list:
            _flatten_nested_list(item, work_list)
        return
    raise ValueError(f'flatten_nested_list should only get lists or JSONNodes as input')


def _initialize_node(outer_container_type: NodeType) -> Union[Dict, List]:
    return {
        NodeType.DICT: {},
        NodeType.LIST: [],
    }[outer_container_type]


def _nodes_to_object(
        nodes: List[Node],
) -> str:
    outer_container_type = nodes[0].keys[0].key_type
    if nodes[0].keys[0].key_type == NodeType.VALUE:
        return json.dumps(nodes[0].keys[0].key)

    end_result = _initialize_node(outer_container_type)

    for node in nodes:
        work_item = end_result
        for (node_type, node_value), (next_node_type, next_node_value) in list(zip(node.keys[:-1], node.keys[1:])):
            if node_type == NodeType.DICT:
                if node_value not in work_item:
                    work_item[node_value] = (
                        next_node_value if next_node_type == NodeType.VALUE else _initialize_node(next_node_type)
                    )
            elif node_type == NodeType.LIST:
                if len(work_item) == node_value:
                    work_item.append(
                        next_node_value if next_node_type == NodeType.VALUE else _initialize_node(next_node_type)
                    )
            work_item = work_item[node_value]
    return json.dumps(end_result)


@dataclass
class JSONData:
    """
    Nested structure of JSON data.
    Can occur in the data section of the HTTP request, but also for example inside of base64-urlencoded cookies or
    parameters.
    """
    json_string: str
    """
    String representation of the JSON data.
    ``json_string`` is not automatically updated when the ``json_nodes`` are updated: use ``.to_json`` instead.
    """

    def __post_init__(self):
        self.json_nodes: List[Node] = Node.from_object(json.loads(self.json_string))

    def to_json(self):
        """
        After modifying the ``json_nodes``, call ``.to_json`` to get a string representation of the JSON data.
        The ``json_string`` is not updated automatically.
        """
        return _nodes_to_object(self.json_nodes)
