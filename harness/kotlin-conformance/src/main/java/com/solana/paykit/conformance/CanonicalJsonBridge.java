package com.solana.paykit.conformance;

import com.solana.paykit.protocols.mpp.core.CanonicalJson;
import kotlinx.serialization.json.JsonElement;

final class CanonicalJsonBridge {
  private CanonicalJsonBridge() {}

  static String encode(JsonElement element) {
    return CanonicalJson.INSTANCE.encode(element);
  }
}
