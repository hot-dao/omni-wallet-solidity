// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library RLPEncode {
  function encodeUint(uint256 _uint, uint8 byteLength) internal pure returns (bytes memory) {
        bytes memory b = new bytes(byteLength);
        for (uint8 i = 0; i < byteLength; i++) {
            b[byteLength - 1 - i] = bytes1(uint8(_uint >> (8 * i)));
        }
        return encodeBytes(b);
    }

    function encodeUint128(uint128 _uint, uint8 byteLength) internal pure returns (bytes memory) {
        return encodeUint(uint256(_uint), byteLength);
    }

    function encodeUint64(uint64 _uint, uint8 byteLength) internal pure returns (bytes memory) {
        return encodeUint(uint256(_uint), byteLength);
    }

    function encodeBytes(bytes memory input) internal pure returns (bytes memory) {
        uint256 length = input.length;

        if (length == 1 && uint8(input[0]) <= 0x7f) {
            // Если длина 1 и значение <= 0x7f, возвращаем как есть
            return input;
        } else if (length <= 55) {
            // Если длина <= 55, используем короткий формат
            bytes memory output = new bytes(1 + length);
            output[0] = bytes1(uint8(0x80 + length));
            for (uint256 i = 0; i < length; i++) {
                output[i + 1] = input[i];
            }
            return output;
        } else {
            // Если длина > 55, используем длинный формат
            uint256 tempLength = length;
            uint256 byteLength = 0;
            while (tempLength != 0) {
                byteLength++;
                tempLength >>= 8;
            }

            bytes memory output = new bytes(1 + byteLength + length);
            output[0] = bytes1(uint8(0xb7 + byteLength));
            // Исправлено: запись байтов длины в правильном порядке
            for (uint256 i = 0; i < byteLength; i++) {
                output[1 + byteLength - 1 - i] = bytes1(uint8(length >> (8 * i)));
            }
            // Копирование данных
            for (uint256 i = 0; i < length; i++) {
                output[1 + byteLength + i] = input[i];
            }
            return output;
        }
    }
    
    function encodeList(bytes[] memory _items) internal pure returns (bytes memory) {
        bytes memory concatenated;
        for (uint256 i = 0; i < _items.length; i++) {
            concatenated = concatenate(concatenated, _items[i]);
        }
        return concatenate(encodeLength(concatenated.length, 192), concatenated);
    }

    function encodeLength(uint256 _length, uint256 _offset) internal pure returns (bytes memory) {
        if (_length < 56) {
            return bytes(abi.encodePacked(uint8(_length + _offset)));
        } else {
            uint256 lenLen;
            uint256 i = 1;
            while (_length / i != 0) {
                lenLen++;
                i *= 256;
            }
            bytes memory b = bytes(abi.encodePacked(uint8(lenLen + _offset + 55)));
            for (i = (lenLen - 1) * 8; i > 0; i -= 8) {
                b = concatenate(b, bytes(abi.encodePacked(uint8(_length / (2 ** i)))));
            }
            return concatenate(b, bytes(abi.encodePacked(uint8(_length))));
        }
    }

    function concatenate(bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        bytes memory result = new bytes(a.length + b.length);

        assembly {
            let resultPtr := add(result, 0x20)
            let aPtr := add(a, 0x20)
            let bPtr := add(b, 0x20)
            let aLength := mload(a)
            let bLength := mload(b)

            // Copy a to result
            for { let i := 0 } lt(i, aLength) { i := add(i, 0x20) } {
                mstore(add(resultPtr, i), mload(add(aPtr, i)))
            }

            // Copy b to result
            for { let i := 0 } lt(i, bLength) { i := add(i, 0x20) } {
                mstore(add(resultPtr, add(aLength, i)), mload(add(bPtr, i)))
            }
        }

        return result;
    }

}
