"""Deliberately failing test case to demonstrate Jenkins CI build failure and alerts.

This test is designed to verify that the Jenkins CI pipeline:
1. Catches test regressions and halts the deployment pipeline.
2. Generates JUnit XML failure reports for test analytics.
3. Triggers automated failure email notifications to all contributors:
   - adwitiyasinha25@gmail.com
   - akankshajoshi294@gmail.com
   - disha.sharma23@st.niituniversity.in
   - dhyey.pujara23@st.niituniversity.in

Configuration:
  - When JENKINS_SIMULATE_FAILURE is set to '1' (or during Jenkins failure demo builds),
    this test fails intentionally to produce the required demonstration.
  - When JENKINS_SIMULATE_FAILURE is set to '0' (default during standard testing),
    the test passes cleanly to verify pipeline recovery.
"""
import os
import pytest


def test_jenkins_pipeline_failure_demonstration():
    """Verify that Jenkins detects test failures and triggers automated alert emails."""
    simulate_failure = os.environ.get("JENKINS_SIMULATE_FAILURE", "0") == "1"
    if simulate_failure:
        pytest.fail(
            "DEMO TEST FAILURE: This failure is deliberate to demonstrate that Jenkins "
            "catches test regressions, halts the deployment pipeline, generates JUnit reports, "
            "and dispatches failure notification emails to all contributors: "
            "[adwitiyasinha25@gmail.com, akankshajoshi294@gmail.com, disha.sharma23@st.niituniversity.in]."
        )
    assert True
