import Foundation
import Testing
@testable import SolanaPayKit

/// Wire-codec parity: the internally-tagged `SessionAction`, salt-as-string,
/// and the `cumulativeAmount`/`cumulative` alias must match the Rust/Go shapes.
@Suite("Session wire codec")
struct SessionWireTests {
    private func encodeToObject(_ action: SessionAction) throws -> [String: Any] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(action)
        return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    @Test
    func openActionFlattensTagAndSerializesSaltAndRecentSlotAsStrings() throws {
        let payload = OpenPayload.paymentChannel(
            mode: .pull, channelId: "Chan", deposit: "1000", payer: "Payer", payee: "Payee",
            mint: "Mint", salt: 42, gracePeriod: 900, recentSlot: 5000, authorizedSigner: "Auth", signature: "Sig"
        )
        let object = try encodeToObject(.open(payload))

        #expect(object["action"] as? String == "open")
        #expect(object["mode"] as? String == "pull")
        #expect(object["channelId"] as? String == "Chan")
        // salt and recentSlot are decimal strings, not numbers.
        #expect(object["salt"] as? String == "42")
        #expect(object["recentSlot"] as? String == "5000")
        #expect(object["authorizedSigner"] as? String == "Auth")
    }

    @Test
    func topUpActionUsesCamelCaseTag() throws {
        let object = try encodeToObject(.topUp(TopUpPayload(channelId: "Chan", newDeposit: "500", signature: "Sig")))
        #expect(object["action"] as? String == "topUp")
        #expect(object["newDeposit"] as? String == "500")
    }

    @Test
    func sessionActionRoundTrips() throws {
        let voucher = SignedVoucher(
            data: VoucherData(channelId: "Chan", cumulative: "250", expiresAt: 4_102_444_800, nonce: 3),
            signature: "Sig"
        )
        let actions: [SessionAction] = [
            .open(OpenPayload.push(channelId: "Chan", deposit: "1000", authorizedSigner: "Auth", signature: "Sig")),
            .voucher(VoucherPayload(voucher: voucher)),
            .commit(CommitPayload(deliveryId: "d1", voucher: voucher)),
            .topUp(TopUpPayload(channelId: "Chan", newDeposit: "500", signature: "Sig")),
            .close(ClosePayload(channelId: "Chan", voucher: voucher)),
        ]
        let encoder = JSONEncoder()
        for action in actions {
            let data = try encoder.encode(action)
            let decoded = try JSONDecoder().decode(SessionAction.self, from: data)
            #expect(decoded == action)
        }
    }

    @Test
    func voucherDataEncodesCumulativeAmountAndReadsAlias() throws {
        let data = VoucherData(channelId: "Chan", cumulative: "250", expiresAt: 100)
        let encoded = try JSONEncoder().encode(data)
        let object = try #require(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        #expect(object["cumulativeAmount"] as? String == "250")
        #expect(object["cumulative"] == nil)

        // Decodes from both the canonical key and the legacy alias.
        let fromCanonical = try JSONDecoder().decode(
            VoucherData.self, from: Data(#"{"channelId":"Chan","cumulativeAmount":"7","expiresAt":1}"#.utf8)
        )
        #expect(fromCanonical.cumulative == "7")
        let fromAlias = try JSONDecoder().decode(
            VoucherData.self, from: Data(#"{"channelId":"Chan","cumulative":"9","expiresAt":1}"#.utf8)
        )
        #expect(fromAlias.cumulative == "9")
    }

    @Test
    func openPayloadReadsSaltAndRecentSlotFromStringOrNumber() throws {
        let fromString = try JSONDecoder().decode(
            OpenPayload.self,
            from: Data(#"{"mode":"pull","salt":"42","recentSlot":"5000","authorizedSigner":"A","signature":"S"}"#.utf8)
        )
        #expect(fromString.salt == 42)
        #expect(fromString.recentSlot == 5000)
        let fromNumber = try JSONDecoder().decode(
            OpenPayload.self,
            from: Data(#"{"mode":"pull","salt":42,"recentSlot":5000,"authorizedSigner":"A","signature":"S"}"#.utf8)
        )
        #expect(fromNumber.salt == 42)
        #expect(fromNumber.recentSlot == 5000)
        // Absent recentSlot decodes as nil (older peers).
        let absent = try JSONDecoder().decode(
            OpenPayload.self,
            from: Data(#"{"mode":"pull","salt":42,"authorizedSigner":"A","signature":"S"}"#.utf8)
        )
        #expect(absent.recentSlot == nil)
    }

    @Test
    func meteringUsageParsesAmountAndRejectsInvalid() throws {
        let usage = MeteringUsage(deliveryId: "d1", amount: "250")
        #expect(try usage.amountBaseUnits() == 250)
        // Round-trips through the wire.
        let decoded = try JSONDecoder().decode(MeteringUsage.self, from: try JSONEncoder().encode(usage))
        #expect(decoded == usage)
        #expect(throws: PayKitError.self) { _ = try MeteringUsage(deliveryId: "d1", amount: "bad").amountBaseUnits() }
    }

    @Test
    func unknownSessionActionTagIsRejected() {
        let json = Data(#"{"action":"frobnicate","channelId":"Chan"}"#.utf8)
        #expect(throws: (any Error).self) { _ = try JSONDecoder().decode(SessionAction.self, from: json) }
    }

    @Test
    func voucherMessageBytesRejectsInvalidCumulative() {
        let data = VoucherData(channelId: "11111111111111111111111111111112", cumulative: "not-a-number", expiresAt: 1)
        #expect(throws: PayKitError.self) { _ = try data.messageBytes() }
    }
}

/// The payment-channel session opener: pull + clientVoucher only, payer-signed
/// open transaction with the operator as fee payer. Mirrors
/// `create_payment_channel_session_opener` and its guard tests.
@Suite("Payment-channel session opener", .serialized)
struct SessionOpenerTests {
    private let operatorAddress = Base58.encode(Data(repeating: 0x05, count: 32))
    private let recipient = Base58.encode(Data(repeating: 0x06, count: 32))
    private let blockhash = Base58.encode(Data(repeating: 0x11, count: 32))
    private let openSlot: UInt64 = 4321

    private func request(
        modes: [SessionMode] = [.pull],
        strategy: SessionPullVoucherStrategy? = .clientVoucher,
        recentSlot: UInt64? = 4321
    ) -> SessionRequest {
        SessionRequest(
            cap: "1000000", currency: "USDC", decimals: 6, network: "localnet",
            operator: operatorAddress, recipient: recipient, modes: modes, pullVoucherStrategy: strategy,
            recentSlot: recentSlot
        )
    }

    private func signers() throws -> (payer: MemorySigner, session: MemorySigner) {
        (try MemorySigner(secretKey: Data(repeating: 1, count: 32)),
         try MemorySigner(secretKey: Data(repeating: 2, count: 32)))
    }

    @Test
    func buildsPullClientVoucherOpenAction() async throws {
        // The slot is challenge-sourced: the opener reads request.recentSlot.
        let (payer, sessionSigner) = try signers()
        let opener = try await PaymentChannelSession.open(
            request: request(), payerSigner: payer, sessionSigner: sessionSigner, recentBlockhash: blockhash
        )

        #expect(opener.session.channelId == opener.open.channelId)
        guard case let .open(payload) = opener.action else {
            Issue.record("expected open action"); return
        }
        #expect(payload.mode == .pull)
        #expect(payload.channelId == opener.open.channelId.base58)
        #expect(payload.payer == (try Pubkey(bytes: payer.publicKey)).base58)
        #expect(payload.authorizedSigner == sessionSigner.address)
        #expect(payload.signature == pendingServerSignature)
        #expect(payload.transaction != nil)
        // The challenge slot threads from the opener into the wire payload's
        // recentSlot (it is a PDA seed the server re-derives).
        #expect(payload.recentSlot == openSlot)
        #expect(opener.open.openSlot == openSlot)
        // localnet USDC resolves to the mainnet mint on the MPP charge path.
        #expect(opener.open.mint.base58 == Mints.usdcMainnet)
        #expect(opener.open.deposit == 1_000_000)
        #expect(opener.open.gracePeriod == PaymentChannels.defaultGracePeriodSeconds)
    }

    @Test
    func appliesSessionOptions() async throws {
        let (payer, sessionSigner) = try signers()
        var options = PaymentChannelSessionOpenOptions()
        options.cumulative = 20
        options.expiresAt = 1234
        let opener = try await PaymentChannelSession.open(
            request: request(), payerSigner: payer, sessionSigner: sessionSigner,
            recentBlockhash: blockhash, options: options
        )
        let voucher = try await opener.session.prepareIncrement(5)
        #expect(voucher.data.cumulative == "25")
        #expect(voucher.data.expiresAt == 1234)
    }

    @Test
    func rejectsNonPullChallenge() async throws {
        let (payer, sessionSigner) = try signers()
        await #expect(throws: PayKitError.self) {
            _ = try await PaymentChannelSession.open(
                request: request(modes: [.push], strategy: nil),
                payerSigner: payer, sessionSigner: sessionSigner, recentBlockhash: blockhash
            )
        }
    }

    @Test
    func rejectsOperatedVoucherChallenge() async throws {
        let (payer, sessionSigner) = try signers()
        await #expect(throws: PayKitError.self) {
            _ = try await PaymentChannelSession.open(
                request: request(strategy: .operatedVoucher),
                payerSigner: payer, sessionSigner: sessionSigner, recentBlockhash: blockhash
            )
        }
    }

    @Test
    func rejectsChallengeWithoutRecentSlot() async throws {
        // recentSlot carries the channel-PDA openSlot seed; without a
        // challenge value or an explicit override the open cannot be derived.
        let (payer, sessionSigner) = try signers()
        await #expect(throws: PayKitError.self) {
            _ = try await PaymentChannelSession.open(
                request: request(recentSlot: nil),
                payerSigner: payer, sessionSigner: sessionSigner, recentBlockhash: blockhash
            )
        }
        // An explicit override rescues a challenge that omitted it.
        let opener = try await PaymentChannelSession.open(
            request: request(recentSlot: nil),
            payerSigner: payer, sessionSigner: sessionSigner, recentBlockhash: blockhash, openSlot: openSlot
        )
        #expect(opener.open.openSlot == openSlot)
    }

    /// The hand-rolled `open` instruction must place `rentPayer` (operator /
    /// fee payer) right after `payer` as a second writable signer, shifting
    /// every later account by +1 (14 accounts total). The on-chain open-tx
    /// verifier reads `payer=0, rentPayer=1, payee=2, mint=3,
    /// authorizedSigner=4, channel=5, ...` and asserts `accounts[1] == operator`.
    @Test
    func openInstructionThreadsRentPayerAfterPayer() throws {
        let payer = try Pubkey(bytes: try MemorySigner(secretKey: Data(repeating: 1, count: 32)).publicKey)
        let rentPayer = try Pubkey(base58: operatorAddress)
        let payee = try Pubkey(base58: recipient)
        let mint = try Pubkey(base58: Mints.usdcMainnet)
        let authorizedSigner = try Pubkey(bytes: try MemorySigner(secretKey: Data(repeating: 2, count: 32)).publicKey)
        let tokenProgram = try Pubkey(base58: Mints.tokenProgram)

        let params = PaymentChannels.OpenChannelParams(
            payer: payer,
            rentPayer: rentPayer,
            payee: payee,
            mint: mint,
            authorizedSigner: authorizedSigner,
            salt: 7,
            deposit: 1_000_000,
            gracePeriod: PaymentChannels.defaultGracePeriodSeconds,
            openSlot: 4321,
            recipients: [],
            tokenProgram: tokenProgram,
            programId: PaymentChannels.programId
        )
        let ix = try PaymentChannels.buildOpenInstruction(params)

        // open account count 13 -> 14.
        #expect(ix.accounts.count == 14)

        // payer = index 0: writable signer.
        #expect(ix.accounts[0].pubkey == payer)
        #expect(ix.accounts[0].isSigner && ix.accounts[0].isWritable)

        // rentPayer = index 1: writable signer (the operator), right after payer.
        #expect(ix.accounts[1].pubkey == rentPayer)
        #expect(ix.accounts[1].isSigner && ix.accounts[1].isWritable)

        // Everything after payer shifted by +1.
        #expect(ix.accounts[2].pubkey == payee)
        #expect(ix.accounts[3].pubkey == mint)
        #expect(ix.accounts[4].pubkey == authorizedSigner)
        // channel PDA at index 5 is writable, non-signer.
        #expect(ix.accounts[5].isWritable && !ix.accounts[5].isSigner)
    }
}
