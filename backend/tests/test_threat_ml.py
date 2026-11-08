"""Tests for the ML training pipeline and SHAP explanation integration."""
from __future__ import annotations

import pytest
from app.modules.threat import _get_model, _ml_predict, analyze
from app.modules.threat.url_features import extract_features
from app.schemas import ScanContext


class TestMLIntegration:
    def test_model_loads_successfully(self):
        model, explainer, feature_names = _get_model()
        assert model is not None, "Trained model should be loadable"
        assert explainer is not None, "SHAP TreeExplainer should be initialized"
        assert len(feature_names) == 20, "Model expects 20 features"

    def test_safe_url_low_ml_risk(self):
        features = extract_features("https://www.google.com/search?q=test")
        score, confidence, findings = _ml_predict(features)
        assert score is not None
        assert score < 30, f"Expected safe score <30, got {score}"
        assert confidence >= 0.8

    def test_phishing_url_high_ml_risk_and_shap(self):
        features = extract_features("http://paypa1-secure-login.tk/verify/account")
        score, confidence, findings = _ml_predict(features)
        assert score is not None
        assert score >= 70, f"Expected phishing score >=70, got {score}"
        assert len(findings) > 0, "Should generate SHAP explanation findings"
        # Findings should be plain-English
        assert all(isinstance(f.title, str) and len(f.title) > 10 for f in findings)
        # Should have stable IDs like THREAT_ML_TLD_RISK
        assert all(f.id.startswith("THREAT_ML_") for f in findings)

    @pytest.mark.asyncio
    async def test_full_analyze_with_ml_and_shap(self):
        ctx = ScanContext()
        res = await analyze("http://paypa1-secure-login.tk/verify/account", ctx)
        assert res.module == "threat"
        assert res.score >= 70
        assert res.confidence >= 0.7
        ml_findings = [f for f in res.findings if f.id.startswith("THREAT_ML_")]
        assert len(ml_findings) >= 1
        # Check SHAP evidence exists
        first_shap = ml_findings[0]
        assert "shap_importance" in first_shap.evidence

