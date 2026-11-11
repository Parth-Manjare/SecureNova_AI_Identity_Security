/**
 * SecureNova - Auth0 Post-Login Risk Guardrail
 *
 * Blocks login when trusted application metadata indicates
 * an elevated identity risk.
 */

exports.onExecutePostLogin = async (event, api) => {
    const metadata = event.user.app_metadata || {};

    const rawScore = metadata.risk_score;
    const riskScore =
        rawScore !== undefined && Number.isFinite(Number(rawScore))
            ? Number(rawScore)
            : 0;

    const riskLevel = String(metadata.risk_level || "low").toLowerCase();

    const highRisk = riskScore >= 80 || riskLevel === "high";

    if (highRisk) {
        console.log("SECURENOVA_RISK_DECISION", JSON.stringify({
            decision: "DENY",
            risk_score: riskScore,
            risk_level: riskLevel,
            reason: "HIGH_RISK_IDENTITY"
        }));

        api.access.deny(
            "risk_detected",
            "Login blocked by SecureNova because the identity risk is elevated."
        );
        return;
    }

    console.log("SECURENOVA_RISK_DECISION", JSON.stringify({
        decision: "ALLOW",
        risk_score: riskScore,
        risk_level: riskLevel,
        reason: "RISK_WITHIN_ACCEPTABLE_THRESHOLD"
    }));
};
