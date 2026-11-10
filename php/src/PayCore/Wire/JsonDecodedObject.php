<?php

declare(strict_types=1);

namespace PayKit\PayCore\Wire;

/**
 * A JSON object decoded by {@see Json::decodePreservingObject()}.
 *
 * Both PHP representations of an object lose wire information, so the
 * members are kept as raw (name, value) pairs instead: array keys coerce
 * the string "0" to int 0 (a plain-array decode of {"0":"x"} would
 * re-encode as the list ["x"]), and property names cannot represent
 * every member either — PHP forbids even creating a property whose name
 * starts with a NUL byte, which is valid JSON ({"\u0000x":1}). The pair
 * list imposes no key transformation at all, so every member round-trips
 * exactly as the wire carried it.
 */
final class JsonDecodedObject
{
    /**
     * @param list<array{0: string, 1: mixed}> $members
     */
    public function __construct(
        public readonly array $members,
    ) {
    }
}
