<?php

declare(strict_types=1);

namespace PayKit\PayCore\Wire;

/**
 * A JSON object decoded by {@see Json::decodePreservingObject()}.
 *
 * PHP arrays would collapse the string key `"0"` to int `0`, so a decoded
 * `{"0":"x"}` would re-encode as the list `["x"]` instead of the object the
 * wire carried. stdClass property names keep their exact string form, and
 * extending stdClass (whose dynamic-property surface this marker deliberately
 * relies on, like json_decode itself) keeps it JSON-shaped while remaining
 * distinguishable from arbitrary `stdClass` payloads, which stay rejected as
 * unsupported values unless empty.
 */
final class JsonDecodedObject extends \stdClass
{
}
