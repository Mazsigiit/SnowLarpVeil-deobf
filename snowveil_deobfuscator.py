import argparse
import hashlib
import json
import math
import os
import re
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


MASK32 = 0xFFFFFFFF
STANDARD_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
PROFILE_SIGNATURE = "f69aa37813f09a1cf961ef59cffc903432b5e868171fdeea9eb65d58b75527d2"
KEYWORDS = set("and break do else elseif end false for function if in local nil not or repeat return then true until while".split())
BUILTINS = set("pcall xpcall type typeof error getfenv setfenv pairs ipairs tonumber table string math bit32 Vector3 CFrame setmetatable getmetatable rawget next".split())
NUMBER = re.compile(r"(?:0[xX][0-9a-fA-F]+(?:\.[0-9a-fA-F]+)?(?:[pP][+-]?\d+)?|0[bB][01]+|(?:\d+\.\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?)")
NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


class DecodeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise DecodeError(message)


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    value: object
    offset: int


def read_quoted(source, start):
    quote = source[start]
    cursor = start + 1
    result = []
    escapes = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
    while cursor < len(source):
        char = source[cursor]
        cursor += 1
        if char == quote:
            return "".join(result), cursor
        if char != "\\":
            require(char not in "\r\n", f"Unescaped newline in string at byte {start}")
            result.append(char)
            continue
        require(cursor < len(source), "Incomplete string escape")
        char = source[cursor]
        cursor += 1
        if char in escapes:
            result.append(escapes[char])
        elif char in "\\\"'":
            result.append(char)
        elif char == "z":
            while cursor < len(source) and source[cursor].isspace():
                cursor += 1
        elif char == "x":
            digits = source[cursor:cursor + 2]
            require(bool(re.fullmatch(r"[0-9a-fA-F]{2}", digits)), "Invalid hexadecimal string escape")
            result.append(chr(int(digits, 16)))
            cursor += 2
        elif char.isdigit():
            digits = char
            while len(digits) < 3 and cursor < len(source) and source[cursor].isdigit():
                digits += source[cursor]
                cursor += 1
            require(int(digits) <= 255, "String escape exceeds one byte")
            result.append(chr(int(digits)))
        elif char in "\r\n":
            if char == "\r" and source[cursor:cursor + 1] == "\n":
                cursor += 1
            result.append("\n")
        else:
            raise DecodeError(f"Unsupported string escape: {char!r}")
    raise DecodeError(f"Unterminated string at byte {start}")


def lex(source):
    tokens = []
    cursor = 0
    while cursor < len(source):
        start = cursor
        char = source[cursor]
        if char.isspace():
            cursor += 1
            continue
        if source.startswith("--", cursor):
            cursor += 2
            match = re.match(r"\[(=*)\[", source[cursor:])
            if match:
                close = "]" + match[1] + "]"
                end = source.find(close, cursor + len(match[0]))
                require(end >= 0, "Unterminated block comment")
                cursor = end + len(close)
            else:
                end = source.find("\n", cursor)
                cursor = len(source) if end < 0 else end + 1
            continue
        if char in "\"'":
            value, cursor = read_quoted(source, cursor)
            tokens.append(Token("string", source[start:cursor], value, start))
            continue
        match = re.match(r"\[(=*)\[", source[cursor:])
        if match:
            close = "]" + match[1] + "]"
            content_start = cursor + len(match[0])
            end = source.find(close, content_start)
            require(end >= 0, "Unterminated long string")
            value = source[content_start:end]
            if value.startswith("\r\n"):
                value = value[2:]
            elif value.startswith("\n"):
                value = value[1:]
            cursor = end + len(close)
            tokens.append(Token("string", source[start:cursor], value, start))
            continue
        match = NAME.match(source, cursor)
        if match:
            cursor = match.end()
            value = match[0]
            tokens.append(Token("keyword" if value in KEYWORDS else "name", value, value, start))
            continue
        match = NUMBER.match(source, cursor)
        if match:
            cursor = match.end()
            value = match[0]
            if value.lower().startswith("0x"):
                number = float.fromhex(value) if "." in value or "p" in value.lower() else int(value, 16)
            elif value.lower().startswith("0b"):
                number = int(value, 2)
            else:
                number = float(value) if "." in value or "e" in value.lower() else int(value)
            tokens.append(Token("number", value, number, start))
            continue
        operator = next((item for item in ("...", "..", "//", "==", "~=", "<=", ">=", "+=", "-=", "::") if source.startswith(item, cursor)), None)
        if operator is None:
            require(char in "+-*/%^#=<>;:,(){}[].", f"Unsupported token at byte {cursor}: {char!r}")
            operator = char
        cursor += len(operator)
        tokens.append(Token("symbol", operator, operator, start))
    return tokens


def literal(tokens, start, depth=0):
    require(depth < 32, "Literal nesting limit exceeded")
    require(start < len(tokens), "Truncated literal")
    token = tokens[start]
    if token.kind in ("number", "string"):
        return token.value, start + 1
    if token.text == "-":
        value, end = literal(tokens, start + 1, depth + 1)
        require(isinstance(value, (int, float)), "Invalid negative literal")
        return -value, end
    if token.text == "(":
        value, end = literal(tokens, start + 1, depth + 1)
        require(tokens[end].text == ")", "Unclosed literal parentheses")
        return value, end + 1
    if token.text == "{":
        values = []
        cursor = start + 1
        while cursor < len(tokens) and tokens[cursor].text != "}":
            value, cursor = literal(tokens, cursor, depth + 1)
            values.append(value)
            if tokens[cursor].text in (",", ";"):
                cursor += 1
            else:
                require(tokens[cursor].text == "}", "Unsupported table literal")
        require(cursor < len(tokens), "Unclosed table literal")
        return values, cursor + 1
    if token.kind == "name" and start + 3 < len(tokens):
        if tokens[start + 1].text == "[" and tokens[start + 2].kind == "number" and tokens[start + 3].text == "]":
            return (token.value, tokens[start + 2].value), start + 4
    raise DecodeError("Expression is not a supported static literal")


def as_integer(value, label):
    require(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and int(value) == value, f"Invalid integer for {label}")
    return int(value)


def xorshift32(value, shifts=(13, 17, 5)):
    value = (value ^ (value << shifts[0])) & MASK32
    value ^= value >> shifts[1]
    return (value ^ (value << shifts[2])) & MASK32


def dot(left, right):
    return sum(a * b for a, b in zip(left, right))


def cross(left, right):
    x, y, z = left
    a, b, c = right
    return y * c - z * b, z * a - x * c, x * b - y * a


def rotate_z(vector, quarter_turns):
    x, y, z = vector
    return ((x, y, z), (-y, x, z), (-x, -y, z), (y, -x, z))[quarter_turns % 4]


def decode85(text, length, alphabet):
    require(isinstance(text, str), "Base85 payload is not a string")
    require(isinstance(length, int) and 0 <= length <= 64 * 1024 * 1024, "Invalid Base85 output size")
    require(len(alphabet) == 85 and len(set(alphabet)) == 85, "Invalid Base85 alphabet")
    require(len(text) == ((length + 3) // 4) * 5, "Base85 length mismatch")
    lookup = {char: index for index, char in enumerate(alphabet)}
    result = bytearray()
    for position in range(0, len(text), 5):
        value = 0
        for char in text[position:position + 5]:
            require(char in lookup, f"Invalid Base85 character at offset {position}")
            value = value * 85 + lookup[char]
        require(value <= MASK32, "Base85 group exceeds 32 bits")
        result.extend(value.to_bytes(4, "big"))
    require(not any(result[length:]), "Nonzero Base85 padding")
    return bytes(result[:length])


def shuffled_alphabet(seed):
    values = [chr(code) for code in range(33, 127) if code not in (34, 92)]
    for length in range(len(values), 1, -1):
        seed = xorshift32(seed)
        index = seed % length
        values[length - 1], values[index] = values[index], values[length - 1]
    return "".join(values[:85])


def decrypt(data, seed_function, block_size=64, shifts=(13, 17, 5)):
    require(block_size > 0, "Invalid cipher block size")
    result = bytearray()
    feedback = 0
    state = 0
    for index, cipher in enumerate(data):
        if index % block_size == 0:
            block = index // block_size
            seed = as_integer(seed_function(block), "cipher seed")
            require(0 < seed <= MASK32, "Cipher seed is outside the supported range")
            state = seed ^ ((block * 65599) & MASK32)
        state = xorshift32(state, shifts)
        result.append(cipher ^ ((state ^ feedback) & 255))
        feedback = (feedback * 31 + cipher) % 16777216
    return bytes(result)


class Reader:
    def __init__(self, data):
        self.data = data
        self.position = 0

    def take(self, length):
        require(isinstance(length, int) and 0 <= length <= len(self.data) - self.position, "Truncated binary payload")
        value = self.data[self.position:self.position + length]
        self.position += length
        return value

    def unpack(self, format_string):
        return struct.unpack(format_string, self.take(struct.calcsize(format_string)))[0]

    def byte(self):
        return self.unpack(">B")

    def varuint(self, max_shift=49, final_limit=15, canonical=True):
        value = 0
        shift = 0
        while True:
            require(shift <= max_shift, "Variable integer is too long")
            byte = self.byte()
            require(shift != max_shift or byte % 128 <= final_limit, "Variable integer overflow")
            value += (byte % 128) << shift
            if byte < 128:
                require(not canonical or shift == 0 or byte != 0, "Noncanonical variable integer")
                return value
            shift += 7

    def zigzag(self):
        value = self.varuint(28, 15, canonical=False)
        return value // 2 if value % 2 == 0 else -(value + 1) // 2

    def finished(self):
        require(self.position == len(self.data), "Unexpected trailing binary data")


def decode_pool(data, maximum_string, expected_count):
    reader = Reader(data)
    values = []
    while reader.position < len(data):
        tag = reader.byte()
        if tag == 2:
            values.append(reader.varuint())
        elif tag in (0, 1):
            length = reader.varuint(28, 127)
            require(length <= maximum_string, "Constant string exceeds the declared limit")
            value = reader.take(length).decode("latin1")
            if tag == 1:
                try:
                    value = float(value)
                except ValueError as error:
                    raise DecodeError("Invalid numeric constant") from error
                require(math.isfinite(value), "Nonfinite numeric constant")
                if value.is_integer():
                    value = int(value)
            values.append(value)
        else:
            raise DecodeError(f"Unknown constant tag {tag}")
    require(len(values) == expected_count, "Decoded constant count mismatch")
    return values


def bootstrap_seed_one(block):
    vector = (226 + (block % 256) * 19, 141, 45)
    other = (22, 22, 23)
    return dot(vector, other) + (dot(cross(vector, other), (14, 1, 14)) + dot(rotate_z(vector, 3), other)) % 1048576


def bootstrap_seed_two(block):
    vector = (1128 + 3 * (block % 256), 535 + 3 * (block % 256), 880)
    other = (24, 14, 15)
    return dot(vector, other) + dot(cross(vector, other), (4, 1, 5)) % 1048576


def bootstrap_seed_three(block, values):
    table = [None] + values
    drift = table[91] * (block % 256)
    x = math.floor((3 * (table[81] + drift) + 3 * (table[79] + table[83]) + table[79]) / 8 + table[72])
    y = math.floor((3 * (table[82] + drift) + 3 * (table[80] + table[84]) + table[80]) / 8 + table[72])
    vector = (x + table[85], y + table[86], table[87])
    other = tuple(table[88:91])
    weights = tuple(table[93:96])
    salt = x % table[98] + 1 + y % table[98] + 1 + (x + y) % table[98] + 1
    mixed = dot(cross(vector, other), weights) + dot(rotate_z(vector, 3), weights) + salt
    return dot(vector, other) + mixed % table[96]


def prototype_seed(parameters, block):
    x_offset, y_offset, width, z, vx, vy, vz, cx, cy, cz, height = parameters
    midpoint_x = math.floor(width / 2 + 0.5)
    midpoint_y = math.floor(3 * height / 4 + 0.5)
    vector = (midpoint_x + x_offset + block % 4096, midpoint_y + y_offset, z)
    other = (vx, vy, vz)
    mixed = dot(cross(vector, other), (cx, cy, cz)) + dot(rotate_z(vector, block), other)
    return dot(vector, other) + mixed % 1048576


def checksum(data):
    value = 0xA5B35705
    for byte in data:
        value ^= byte
        value = (value ^ (value << 5)) & MASK32
        value ^= value >> 7
        value = (value + 0x9E3779B9) & MASK32
    return value


def shape_signature(tokens, masked):
    names = {}
    normalized = []
    for index, token in enumerate(tokens):
        if index in masked:
            normalized.append("DATA")
        elif token.kind == "name" and token.value not in BUILTINS:
            if token.value not in names:
                names[token.value] = f"name_{len(names)}"
            normalized.append(names[token.value])
        else:
            normalized.append(token.kind + ":" + json.dumps(token.value, ensure_ascii=True))
    return hashlib.sha256("\n".join(normalized).encode()).hexdigest()


def extract_layout(tokens):
    tables = []
    masked = set()
    for start, token in enumerate(tokens):
        if token.text != "{":
            continue
        try:
            value, end = literal(tokens, start)
        except (DecodeError, IndexError):
            continue
        tables.append((start, end, value))
    bootstrap = []
    segments = []
    parameter_matrices = []
    permutation_matrices = []
    for start, end, value in tables:
        if value and all(isinstance(item, str) for item in value) and start >= 2:
            if tokens[start - 1].text == "(" and tokens[start - 2].kind == "name" and tokens[end].text == ",":
                previous_locals = [index for index in range(max(0, start - 24), start) if tokens[index].text == "local"]
                require(len(previous_locals) >= 2, "Missing bootstrap size declaration")
                declaration = previous_locals[-2]
                length, length_end = literal(tokens, declaration + 3)
                bootstrap.append((value, length))
                masked.update(index for index in range(start, end) if tokens[index].kind == "string")
                if isinstance(length, int):
                    masked.update(range(declaration + 3, length_end))
        if len(value) == 3 and value[0] == 3 and isinstance(value[2], int) and isinstance(value[1], (str, tuple)):
            if start >= 5 and tokens[start - 1].text == "=" and tokens[start - 2].text == "]":
                key = (tokens[start - 5].value, tokens[start - 3].value)
                segments.append((key, value[1], value[2]))
                masked.update(index for index in range(start, end) if tokens[index].kind == "string")
                masked.add(end - 2)
        if len(value) == 1 and isinstance(value[0], list) and len(value[0]) == 4:
            rows = value[0]
            if all(isinstance(row, list) and len(row) == 11 and all(isinstance(item, int) for item in row) for row in rows):
                parameter_matrices.append(rows)
                masked.update(index for index in range(start, end) if tokens[index].kind == "number")
            if all(isinstance(row, list) and sorted(row) == [1, 2, 3, 4] for row in rows):
                permutation_matrices.append(rows)
                masked.update(index for index in range(start, end) if tokens[index].kind == "number")
    require(len(bootstrap) == 3, f"Expected three bootstrap pools, found {len(bootstrap)}")
    require(len(parameter_matrices) == 1, "Cannot identify a unique prototype key matrix")
    require(len(permutation_matrices) == 1, "Cannot identify a unique operand permutation matrix")
    require(len(segments) == 9 and len({key for key, _, _ in segments}) == 9, "Unexpected encrypted segment layout")
    segment_keys = {key for key, _, _ in segments}
    groups = [value for _, _, value in tables if value and all(isinstance(item, tuple) and item in segment_keys for item in value)]
    require(len(groups) == 4, "Cannot identify four encrypted prototype assemblies")
    descriptors = []
    for start, token in enumerate(tokens):
        if token.text != "return":
            continue
        values = []
        cursor = start + 1
        for index in range(4):
            if cursor >= len(tokens) or tokens[cursor].kind != "number":
                break
            values.append(tokens[cursor].value)
            cursor += 1
            if index < 3:
                if tokens[cursor].text != ",":
                    break
                cursor += 1
        if len(values) == 4 and values[0] == 0 and values[1] in (0, 1) and values[2] > 0 and 0 <= values[3] <= MASK32:
            descriptors.append(values)
            masked.add(start + 5)
            masked.add(start + 7)
    require(len(descriptors) == 4, "Cannot identify prototype checksum descriptors")
    shuffle_seeds = []
    for index in range(3, len(tokens) - 1):
        if tokens[index].kind == "number" and tokens[index - 1].text == "=" and tokens[index - 3].text == "local" and tokens[index + 1].text == "for":
            if 65536 < tokens[index].value <= MASK32 and tokens[index + 4].text == "#":
                shuffle_seeds.append(tokens[index].value)
                masked.add(index)
    require(len(shuffle_seeds) == 1, "Cannot identify the Base85 shuffle seed")
    signature = shape_signature(tokens, masked)
    require(signature == PROFILE_SIGNATURE, f"Unsupported SnowVeil runtime profile: {signature}. No guessed decompilation was produced.")
    return {
        "signature": signature,
        "bootstrap": bootstrap,
        "segments": segments,
        "groups": [groups[index] for index in (0, 1, 3, 2)],
        "descriptors": [descriptors[index] for index in (0, 1, 3, 2)],
        "parameters": parameter_matrices[0],
        "permutations": permutation_matrices[0],
        "shuffle_seed": shuffle_seeds[0],
    }


def parse_prototype(data, identifier, permutation):
    reader = Reader(data)
    require(reader.unpack(">I") == 36224748, "Invalid prototype magic")
    require(reader.unpack(">H") == 1 and reader.unpack(">H") == 7, "Unsupported prototype format version")
    upvalue_count = reader.unpack(">H")
    vararg = reader.byte()
    parameter_count = reader.unpack(">H")
    constant_count = reader.unpack(">I")
    code_size = reader.unpack(">I")
    schema_count = reader.unpack(">H")
    require(vararg in (0, 1), "Invalid vararg flag")
    require(constant_count <= len(data) and schema_count <= 256, "Implausible prototype counts")
    code = reader.take(code_size)
    constants = []
    for _ in range(constant_count):
        tag = reader.byte()
        if tag == 0:
            value = None
        elif tag == 1:
            value = reader.take(reader.unpack(">I")).decode("latin1")
        elif tag == 2:
            byte = reader.byte()
            require(byte in (0, 1), "Invalid boolean constant")
            value = bool(byte)
        elif tag == 3:
            value = reader.unpack(">d")
            require(math.isfinite(value), "Nonfinite prototype constant is not supported")
        else:
            raise DecodeError(f"Unsupported prototype constant tag {tag}")
        constants.append(value)
    upvalues = []
    for _ in range(upvalue_count):
        index = reader.unpack(">H")
        mode = reader.byte()
        require(mode in (0, 1), "Invalid upvalue mode")
        upvalues.append({"index": index, "mode": mode})
    schemas = {}
    for _ in range(schema_count):
        opcode = reader.byte()
        group_count = reader.byte()
        require(opcode not in schemas and group_count > 0, "Invalid or repeated opcode schema")
        groups = [(reader.byte(), reader.byte()) for _ in range(group_count)]
        require(sum(count for count, _ in groups) <= len(permutation), "Too many instruction operands")
        schemas[opcode] = groups
    reader.finished()
    reader = Reader(code)
    instructions = []
    while reader.position < len(code):
        pc = reader.position + 1
        opcode = reader.byte()
        require(opcode in schemas, f"Unknown opcode {opcode} in function {identifier}")
        operands = []
        for count, mask in schemas[opcode]:
            for index in range(count):
                operands.append(reader.unpack("<i") if mask & (1 << index) else reader.zigzag())
        columns = dict(zip(permutation, operands))
        instructions.append({"pc": pc, "next_pc": reader.position + 1, "opcode": opcode, "wire_operands": operands, "columns": columns})
    prototype = {
        "id": identifier,
        "parameter_count": parameter_count,
        "is_vararg": bool(vararg),
        "constants": constants,
        "upvalues": upvalues,
        "code_size": code_size,
        "operand_permutation": permutation,
        "schemas": schemas,
        "instructions": instructions,
        "checksum": checksum(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    lift_prototype(prototype)
    return prototype


def register_index(identifier, value):
    if identifier == 3:
        return (value - 6) & 7
    offset = {1: 3, 2: 2, 4: 0}[identifier]
    return ((value - offset) * 3) & 3


def lift_prototype(prototype):
    identifier = prototype["id"]
    opcodes = {
        1: {23: "GLOBAL_MOVE", 220: "CALL", 118: "RETURN"},
        2: {125: "GLOBAL_MOVE", 137: "CALL", 55: "RETURN"},
        3: {70: "RETURN", 112: "CALL", 128: "JUMP", 144: "JUMP_IF_FALSE", 218: "MOVE_CONSTANT", 225: "CLOSURE"},
        4: {16: "RETURN", 127: "GLOBAL_MOVE", 170: "CALL"},
    }[identifier]
    register = lambda value: register_index(identifier, value)
    boundaries = {instruction["pc"] for instruction in prototype["instructions"]} | {prototype["code_size"] + 1}
    for instruction in prototype["instructions"]:
        opcode = instruction["opcode"]
        require(opcode in opcodes, f"Unsupported handler {opcode} in function {identifier}")
        operation = opcodes[opcode]
        columns = instruction["columns"]
        try:
            if operation == "GLOBAL_MOVE":
                first, second, third, fourth = (columns[index] for index in ((4, 3, 2, 1) if identifier == 4 else (3, 1, 2, 4)))
                arguments = {"destination": register(first), "constant": second, "move_destination": register(third), "move_source": register(fourth)}
            elif operation == "CALL":
                order = {1: (3, 1, 4), 2: (4, 1, 3), 3: (3, 2, 1), 4: (2, 4, 3)}[identifier]
                base, count, results = (columns[index] for index in order)
                arguments = {"base": register(base), "argument_count": count, "result_count": results}
                require(count >= -1 and results >= -1, "Invalid call arity")
            elif operation == "RETURN":
                base, count = (columns[index] for index in {1: (1, 3), 2: (3, 1), 3: (2, 1), 4: (4, 3)}[identifier])
                arguments = {"base": register(base), "count": count}
                require(count >= -1, "Invalid return arity")
            elif operation == "JUMP":
                arguments = {"target": instruction["next_pc"] + columns[2]}
            elif operation == "JUMP_IF_FALSE":
                arguments = {"register": register(columns[1]), "target": instruction["next_pc"] + columns[2]}
            elif operation == "MOVE_CONSTANT":
                arguments = {"destination": register(columns[1]), "source": register(columns[2]), "constant_destination": register(columns[4]), "constant": columns[3]}
            elif operation == "CLOSURE":
                arguments = {"destination": register(columns[1]), "prototype": columns[2] + 1}
                require(1 <= arguments["prototype"] <= 4, "Invalid closure prototype")
            else:
                raise DecodeError("Unsupported operation")
        except KeyError as error:
            raise DecodeError(f"Missing operand for {operation}") from error
        if "constant" in arguments:
            require(0 <= arguments["constant"] < len(prototype["constants"]), "Constant index out of bounds")
        if "target" in arguments:
            require(arguments["target"] in boundaries, "Jump target is not an instruction boundary")
        instruction["operation"] = operation
        instruction["arguments"] = arguments


def lua_literal(value):
    if value is None:
        return "nil"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        chars = []
        for char in value:
            code = ord(char)
            if char in ('"', "\\"):
                chars.append("\\" + char)
            elif 32 <= code <= 126:
                chars.append(char)
            else:
                require(code <= 255, "Constant is not a byte string")
                chars.append(f"\\{code:03d}")
        return '"' + "".join(chars) + '"'
    require(isinstance(value, (int, float)) and math.isfinite(value), "Unsupported Lua literal")
    return str(value)


def global_expression(name):
    require(isinstance(name, str), "Global name is not a string")
    if NAME.fullmatch(name) and name not in KEYWORDS:
        return name
    return f"getfenv()[{lua_literal(name)}]"


def emit_readable(prototypes, entry=3):
    lines = []
    for prototype in prototypes:
        require(not prototype["upvalues"], "Readable output does not support captured upvalues")
        parameter_names = [f"argument_{index + 1}" for index in range(prototype["parameter_count"])]
        if prototype["is_vararg"]:
            parameter_names.append("...")
        lines.append(f"local function function_{prototype['id']}({', '.join(parameter_names)})")
        count = 8 if prototype["id"] == 3 else 4
        lines.append("    local " + ", ".join(f"r{index}" for index in range(count)))
        for index in range(prototype["parameter_count"]):
            require(index < count, "Too many parameters for the supported register layout")
            lines.append(f"    r{index} = argument_{index + 1}")
        instructions = {item["pc"]: item for item in prototype["instructions"]}
        visited = set()

        def block(pc, stop, depth):
            require(depth <= 32, "Control-flow nesting limit exceeded")
            indent = "    " * depth
            while pc != stop and pc <= prototype["code_size"]:
                require(pc in instructions and pc not in visited, "Control flow cannot be safely structured")
                visited.add(pc)
                instruction = instructions[pc]
                operation = instruction["operation"]
                args = instruction["arguments"]
                next_pc = instruction["next_pc"]
                if operation == "GLOBAL_MOVE":
                    name = global_expression(prototype["constants"][args["constant"]])
                    lines.append(f"{indent}r{args['destination']} = {name}")
                    lines.append(f"{indent}r{args['move_destination']} = r{args['move_source']}")
                elif operation == "MOVE_CONSTANT":
                    lines.append(f"{indent}r{args['destination']} = r{args['source']}")
                    lines.append(f"{indent}r{args['constant_destination']} = {lua_literal(prototype['constants'][args['constant']])}")
                elif operation == "CLOSURE":
                    lines.append(f"{indent}r{args['destination']} = function_{args['prototype']}")
                elif operation == "CALL":
                    require(args["argument_count"] >= 0 and args["result_count"] == 0, "Readable output requires fixed-arity calls without captured results")
                    arguments = ", ".join(f"r{index}" for index in range(args["base"] + 1, args["base"] + 1 + args["argument_count"]))
                    lines.append(f"{indent}r{args['base']}({arguments})")
                elif operation == "RETURN":
                    require(args["count"] >= 0, "Readable output requires a fixed return count")
                    values = ", ".join(f"r{index}" for index in range(args["base"], args["base"] + args["count"]))
                    lines.append(indent + "return" + (" " + values if values else ""))
                    return next_pc
                elif operation == "JUMP":
                    require(args["target"] >= next_pc, "Backward jumps require a different structuring profile")
                    if args["target"] == stop:
                        return stop
                    pc = args["target"]
                    continue
                elif operation == "JUMP_IF_FALSE":
                    target = args["target"]
                    require(target > pc, "Backward conditional branches are not supported")
                    predecessors = [item for item in prototype["instructions"] if item["next_pc"] == target and item["pc"] >= next_pc]
                    require(len(predecessors) == 1 and predecessors[0]["operation"] == "JUMP", "Cannot identify the conditional merge")
                    merge = predecessors[0]["arguments"]["target"]
                    require(merge >= target, "Invalid conditional merge")
                    lines.append(f"{indent}if r{args['register']} then")
                    block(next_pc, merge, depth + 1)
                    if target != merge:
                        lines.append(indent + "else")
                        block(target, merge, depth + 1)
                    lines.append(indent + "end")
                    pc = merge
                    continue
                pc = next_pc
            return pc

        block(1, prototype["code_size"] + 1, 1)
        require(len(visited) == len(instructions), "Readable output would omit instructions")
        lines.extend(["end", ""])
    lines.append(f"return function_{entry}(...)")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Symbol:
    kind: str
    value: object


def simplify(prototypes, entry=3):
    by_id = {prototype["id"]: prototype for prototype in prototypes}
    events = []
    trace = []
    step_count = 0

    def walk(identifier, parameters, depth=0):
        nonlocal step_count
        require(depth < 32, "Symbolic call-depth limit exceeded")
        prototype = by_id[identifier]
        require(not prototype["upvalues"], "Symbolic simplification cannot resolve captured upvalues")
        registers = {index: parameters[index] if index < len(parameters) else Symbol("constant", None) for index in range(prototype["parameter_count"])}
        instructions = {instruction["pc"]: instruction for instruction in prototype["instructions"]}
        pc = 1
        while pc <= prototype["code_size"]:
            step_count += 1
            require(step_count <= 10000, "Symbolic step limit exceeded")
            require(pc in instructions, "Invalid symbolic program counter")
            instruction = instructions[pc]
            operation = instruction["operation"]
            args = instruction["arguments"]
            trace.append({"prototype": identifier, "pc": pc, "operation": operation})
            next_pc = instruction["next_pc"]
            if operation == "GLOBAL_MOVE":
                registers[args["destination"]] = Symbol("global", prototype["constants"][args["constant"]])
                registers[args["move_destination"]] = registers.get(args["move_source"], Symbol("constant", None))
            elif operation == "MOVE_CONSTANT":
                registers[args["destination"]] = registers.get(args["source"], Symbol("constant", None))
                registers[args["constant_destination"]] = Symbol("constant", prototype["constants"][args["constant"]])
            elif operation == "CLOSURE":
                registers[args["destination"]] = Symbol("closure", args["prototype"])
            elif operation == "JUMP":
                next_pc = args["target"]
            elif operation == "JUMP_IF_FALSE":
                condition = registers.get(args["register"], Symbol("constant", None))
                require(condition.kind in ("constant", "closure"), "Branch condition depends on the external environment")
                truth = condition.kind == "closure" or (condition.value is not None and condition.value is not False)
                if not truth:
                    next_pc = args["target"]
            elif operation == "CALL":
                require(args["argument_count"] >= 0 and args["result_count"] == 0, "Symbolic calls require fixed arguments and unused results")
                function = registers.get(args["base"], Symbol("constant", None))
                arguments = [registers.get(index, Symbol("constant", None)) for index in range(args["base"] + 1, args["base"] + 1 + args["argument_count"])]
                if function.kind == "closure":
                    walk(function.value, arguments, depth + 1)
                elif function.kind == "global":
                    require(all(argument.kind == "constant" for argument in arguments), "External call arguments are not constant")
                    events.append({"global": function.value, "arguments": [argument.value for argument in arguments]})
                else:
                    raise DecodeError("Call target cannot be statically resolved")
            elif operation == "RETURN":
                require(args["count"] == 0, "Symbolic simplification cannot discard return values")
                return
            pc = next_pc

    walk(entry, [])
    lines = [f"{global_expression(event['global'])}({', '.join(lua_literal(value) for value in event['arguments'])})" for event in events]
    return "\n".join(lines) + "\n", events, trace


def disassemble(prototypes):
    lines = []
    for prototype in prototypes:
        lines.append(f"Function {prototype['id']}: parameters={prototype['parameter_count']}, vararg={prototype['is_vararg']}, checksum={prototype['checksum']:08x}")
        for index, constant in enumerate(prototype["constants"]):
            lines.append(f"  K{index} = {lua_literal(constant)}")
        for instruction in prototype["instructions"]:
            arguments = ", ".join(f"{key}={value}" for key, value in instruction["arguments"].items())
            lines.append(f"  {instruction['pc']:04d} -> {instruction['next_pc']:04d}  {instruction['opcode']:3d}  {instruction['operation']:<16} {arguments}")
        lines.append("")
    return "\n".join(lines)


def deobfuscate(source):
    layout = extract_layout(lex(source))
    stage_one_chunks, stage_one_size = layout["bootstrap"][0]
    stage_two_chunks, stage_two_size = layout["bootstrap"][1]
    require(isinstance(stage_one_size, int) and isinstance(stage_two_size, int), "Unexpected bootstrap size expressions")
    first_raw = decrypt(decode85("".join(stage_one_chunks), stage_one_size, STANDARD_ALPHABET), bootstrap_seed_one)
    first = decode_pool(first_raw, 18, 20)
    expected_first = ["Instance", "ScreenGui", "Frame", "Path2D", "Enabled", "Size", "Parent", "Visible", "SetControlPoints", "GetPositionOnCurve", "X", "Scale", "Offset", "Y", "Z", "Dot", "Cross", "Destroy", "UDim2", "Path2DControlPoint"]
    require(first == expected_first, "Bootstrap API table does not match the supported runtime")
    second_raw = decrypt(decode85("".join(stage_two_chunks), stage_two_size, STANDARD_ALPHABET), bootstrap_seed_two)
    second = decode_pool(second_raw, 27, 121)
    require(second[70:78] == [256, 0.5, 13, 17, 5, 255, 128, 7], "Unsupported arithmetic configuration")
    require(second[91] == 64 and second[95] == 1048576 and second[97] > 0, "Unsupported bootstrap cipher parameters")
    third_chunks, third_size_reference = layout["bootstrap"][2]
    require(isinstance(third_size_reference, tuple) and third_size_reference[1] == 121, "Invalid final bootstrap size reference")
    third_size = as_integer(second[120], "third pool size")
    third_raw = decrypt(decode85("".join(third_chunks), third_size, STANDARD_ALPHABET), lambda block: bootstrap_seed_three(block, second))
    third = decode_pool(third_raw, 60, 34)
    require(third[27:33] == [">I4", ">I2", ">I1", "", ">d", "<i4"], "Unsupported binary field formats")
    alphabet = shuffled_alphabet(layout["shuffle_seed"])
    decoded_segments = {}
    segment_report = []
    for key, value, size in layout["segments"]:
        if isinstance(value, tuple):
            require(1 <= value[1] <= len(third), "Segment string reference is out of bounds")
            value = third[value[1] - 1]
        require(1 <= size <= 72, "Invalid segment size")
        decoded_segments[key] = decode85(value, size, alphabet)
        segment_report.append({"table": key[0], "index": key[1], "size": size})
    prototypes = []
    binaries = {}
    for index in range(4):
        encrypted = b"".join(decoded_segments[key] for key in layout["groups"][index])
        parameters = layout["parameters"][index]
        data = decrypt(encrypted, lambda block: prototype_seed(parameters, block), 128)
        compression, flag, expected_size, expected_checksum = layout["descriptors"][index]
        require(compression == 0 and flag in (0, 1), "Unsupported prototype compression mode")
        require(len(data) == expected_size, f"Function {index + 1} size mismatch")
        require(checksum(data) == expected_checksum, f"Function {index + 1} checksum mismatch")
        prototype = parse_prototype(data, index + 1, layout["permutations"][index])
        prototype["key_parameters"] = parameters
        prototype["size"] = expected_size
        prototype["expected_checksum"] = expected_checksum
        prototype["checksum_verified"] = True
        prototypes.append(prototype)
        binaries[f"prototype_{index + 1}.bin"] = data
    readable = emit_readable(sorted(prototypes, key=lambda prototype: (prototype["id"] == 3, prototype["id"])))
    simplified, events, trace = simplify(prototypes)
    report = {
        "format": "SnowVeil v1 observed four-prototype runtime",
        "runtime_signature": layout["signature"],
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "execution": "Static decoding and symbolic control-flow analysis only; no Lua or external call was executed.",
        "entry_prototype": 3,
        "bootstrap_pools": {"api_names": first, "configuration": second, "runtime_strings": third},
        "base85_shuffle_seed": layout["shuffle_seed"],
        "custom_base85_alphabet": alphabet,
        "segments": segment_report,
        "prototypes": prototypes,
        "statically_predicted_calls": events,
        "symbolic_trace": trace,
        "limitations": [
            "Supports the validated runtime layout in the supplied sample, including reformatted and consistently renamed copies; it is not a universal SnowVeil decompiler.",
            "Original identifier names, comments, and exact source formatting are not encoded in the recovered payload.",
            "Readable Lua preserves the payload control flow under an ordinary, unmodified Lua/Luau function environment; the obfuscator's Roblox environment checks and debug stack emulation are omitted.",
            "The simplified output preserves the statically resolved external calls; introspection, modified function environments, and stack-sensitive error behavior can differ.",
            "Checksums validate the decoded bytes against this file's metadata; they are not cryptographic authenticity checks.",
        ],
    }
    binaries.update({"bootstrap_1.bin": first_raw, "bootstrap_2.bin": second_raw, "bootstrap_3.bin": third_raw})
    return {"lua": readable, "simplified": simplified, "disassembly": disassemble(prototypes), "report": report, "binaries": binaries}


def write_outputs(items, input_path, force=False):
    resolved = [path.resolve() for path, _ in items]
    require(len(set(resolved)) == len(resolved), "Output paths must be distinct")
    require(input_path.resolve() not in resolved, "Refusing to overwrite the input file")
    for path, _ in items:
        require(not path.is_symlink(), f"Refusing a symbolic-link output: {path}")
        require(force or not path.exists(), f"Output already exists: {path}. Use --force to replace it.")
        require(not path.exists() or path.is_file(), f"Output is not a regular file: {path}")
    for path, data in items:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".snowveil-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data if isinstance(data, bytes) else data.encode("utf-8"))
            if force:
                os.replace(temporary, path)
            else:
                os.link(temporary, path)
                os.unlink(temporary)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Statically deobfuscate the validated SnowVeil v1 four-prototype profile. Never executes Lua.")
    parser.add_argument("input", type=Path, help="Input SnowVeil Lua file")
    parser.add_argument("-o", "--output", type=Path, help="Recovered Lua output path")
    parser.add_argument("--simplified", type=Path, help="Write statically simplified Lua")
    parser.add_argument("--report", type=Path, help="Write the full JSON analysis report")
    parser.add_argument("--disassembly", type=Path, help="Write the VM instruction listing")
    parser.add_argument("--dump-dir", type=Path, help="Write decrypted pools and prototype binary files")
    parser.add_argument("--force", action="store_true", help="Replace existing output files")
    parser.add_argument("--max-input-mib", type=int, default=16, help="Maximum input size in MiB, default: 16")
    arguments = parser.parse_args(argv)
    try:
        require(1 <= arguments.max_input_mib <= 64, "Input limit must be between 1 and 64 MiB")
        require(arguments.input.is_file(), "Input is not a regular file")
        require(arguments.input.stat().st_size <= arguments.max_input_mib * 1024 * 1024, "Input exceeds the configured size limit")
        source = arguments.input.read_text(encoding="utf-8-sig")
        result = deobfuscate(source)
        output = arguments.output or arguments.input.with_name(arguments.input.stem + ".deobfuscated.lua")
        items = [(output, result["lua"])]
        if arguments.simplified:
            items.append((arguments.simplified, result["simplified"]))
        if arguments.report:
            items.append((arguments.report, json.dumps(result["report"], indent=2, ensure_ascii=True, allow_nan=False) + "\n"))
        if arguments.disassembly:
            items.append((arguments.disassembly, result["disassembly"]))
        if arguments.dump_dir:
            items.extend((arguments.dump_dir / name, value) for name, value in result["binaries"].items())
        write_outputs(items, arguments.input, arguments.force)
        print(f"Decoded 3 constant pools, 9 segments, and 4 prototypes. All prototype checksums match.")
        print(f"Recovered Lua: {output}")
        for event in result["report"]["statically_predicted_calls"]:
            print(f"Predicted call: {global_expression(event['global'])}({', '.join(lua_literal(value) for value in event['arguments'])})")
        return 0
    except (DecodeError, OSError, UnicodeError, ValueError, struct.error, IndexError, KeyError, OverflowError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
