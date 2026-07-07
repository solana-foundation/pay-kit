# Server-side usage (`upto`): charge for actual usage up to a ceiling.
#
# Mirrors the summarize route in examples/playground_api/app.py. Not one of the
# playground's four primitives, so the playground extractor ignores it — the SDK
# docs read it directly. See ../../../docs/snippets-convention.md.
import solana_pay_kit
from fastapi import Depends, FastAPI, Request
from solana_pay_kit import Gate, Protocol, usd
from solana_pay_kit.fastapi import Charge, RequireUsage, install

solana_pay_kit.configure(network="solana_localnet")

# snippet:start
# A usage gate authorizes a ceiling (x402 `upto`); the handler meters actual
# consumption via the Charge dependency and the gate settles that amount after
# the request, refunding the remainder. Usage gates are x402-only.
summarize_gate = Gate.build(
    name="summarize",
    amount=usd("0.10"),
    description="Summarize text, billed per token",
    default_pay_to=solana_pay_kit.config().effective_recipient(),
    accept=(Protocol.X402,),
)

app = FastAPI()
install(app)  # maps PayKitError -> 402 challenge


@app.post("${PATH}")
async def summarize(request: Request, charge: Charge = Depends(RequireUsage(summarize_gate))) -> dict:
    body = await request.body()
    tokens = max(1, len(body) // 4)
    charge.charge(tokens * 100)  # actual base units consumed
    return {"tokens": tokens}


# snippet:end
