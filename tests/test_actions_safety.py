import pytest
from unittest.mock import patch, MagicMock
import actions_ssh
import actions_network


class TestSSHPreconditions:
    def test_password_auth_refused_without_keys(self):
        """Disabling password auth when no authorized_keys exist should be blocked."""
        with patch.object(actions_ssh, "_find_authorized_keys", return_value=False):
            plan = actions_ssh._build_ssh_plan("PasswordAuthentication", "no", lockout_check=True, lockout_value="no")
            assert len(plan["blockers"]) == 1
            assert "No valid SSH public key" in plan["blockers"][0]

    def test_password_auth_allowed_with_keys(self):
        """Disabling password auth when authorized_keys exist should be allowed."""
        with patch.object(actions_ssh, "_find_authorized_keys", return_value=True):
            plan = actions_ssh._build_ssh_plan("PasswordAuthentication", "no", lockout_check=True, lockout_value="no")
            assert len(plan["blockers"]) == 0

    def test_root_login_refused_without_keys(self):
        """Restricting root login when no authorized_keys exist should be blocked."""
        with patch.object(actions_ssh, "_find_authorized_keys", return_value=False):
            plan = actions_ssh._build_ssh_plan("PermitRootLogin", "prohibit-password", lockout_check=True, lockout_value="prohibit-password")
            assert len(plan["blockers"]) == 1

    def test_root_login_allowed_with_keys(self):
        """Restricting root login when authorized_keys exist should be allowed."""
        with patch.object(actions_ssh, "_find_authorized_keys", return_value=True):
            plan = actions_ssh._build_ssh_plan("PermitRootLogin", "prohibit-password", lockout_check=True, lockout_value="prohibit-password")
            assert len(plan["blockers"]) == 0

    def test_non_lockout_action_no_blockers(self):
        """Non-lockout actions should have no blockers."""
        plan = actions_ssh._build_ssh_plan("MaxAuthTries", "3")
        assert len(plan["blockers"]) == 0


class TestSSHValidators:
    def test_ssh_validate_commands_attached(self):
        """SSH actions should have sshd -t validator."""
        plan = actions_ssh._build_ssh_plan("PasswordAuthentication", "no")
        assert plan["validate_commands"] == [["sshd", "-t"]]

    def test_ssh_risky_remote_flag(self):
        """SSH actions should be flagged as risky_remote."""
        plan = actions_ssh._build_ssh_plan("PasswordAuthentication", "no")
        assert plan["risky_remote"] is True

    def test_ssh_precondition_callable(self):
        """SSH actions should have a precondition callable."""
        plan = actions_ssh._build_ssh_plan("PasswordAuthentication", "no")
        assert callable(plan["precondition"])


class TestNetworkPreconditions:
    def test_ufw_baseline_refused_without_ssh_ports(self):
        """UFW baseline should be refused if SSH ports cannot be determined."""
        with patch.object(actions_network, "_ufw_installed", return_value=True),              patch.object(actions_network, "_detect_ssh_ports", return_value=[]):
            plan = actions_network._build_ufw_baseline()
            assert len(plan["blockers"]) == 1
            assert "Could not determine the SSH port" in plan["blockers"][0]

    def test_ufw_baseline_allowed_with_ssh_ports(self):
        """UFW baseline should be allowed if SSH ports are found."""
        with patch.object(actions_network, "_ufw_installed", return_value=True),              patch.object(actions_network, "_detect_ssh_ports", return_value=[22]):
            plan = actions_network._build_ufw_baseline()
            assert len(plan["blockers"]) == 0

    def test_docker_user_refused_without_ssh_ports(self):
        """Docker-User isolation should be refused if SSH ports cannot be determined."""
        with patch.object(actions_network, "_docker_installed", return_value=True), \
             patch.object(actions_network, "_ufw_installed", return_value=True), \
             patch.object(actions_network, "_detect_ssh_ports", return_value=[]):
            plan = actions_network._build_docker_user_isolation()
            assert len(plan["blockers"]) == 1
            assert "Could not determine SSH ports" in plan["blockers"][0]

    def test_docker_user_allowed_with_ssh_ports(self):
        """Docker-User isolation should be allowed if SSH ports are found."""
        with patch.object(actions_network, "_docker_installed", return_value=True), \
             patch.object(actions_network, "_ufw_installed", return_value=True), \
             patch.object(actions_network, "_detect_ssh_ports", return_value=[22]):
            plan = actions_network._build_docker_user_isolation()
            assert len(plan["blockers"]) == 0


class TestNetworkValidators:
    def test_ufw_validate_commands_attached(self):
        """UFW actions should have ufw status validator."""
        with patch.object(actions_network, "_ufw_installed", return_value=True), \
             patch.object(actions_network, "_detect_ssh_ports", return_value=[22]):
            plan = actions_network._build_ufw_baseline()
            assert plan["validate_commands"] == [["ufw", "status"]]

    def test_ufw_risky_remote_flag(self):
        """UFW actions should be flagged as risky_remote."""
        plan = actions_network._build_ufw_baseline()
        assert plan["risky_remote"] is True

    def test_ufw_precondition_callable(self):
        """UFW actions should have a precondition callable."""
        plan = actions_network._build_ufw_baseline()
        assert callable(plan["precondition"])

    def test_docker_user_validate_commands_attached(self):
        """Docker-User actions should have ufw status validator."""
        with patch.object(actions_network, "_docker_installed", return_value=True), \
             patch.object(actions_network, "_ufw_installed", return_value=True), \
             patch.object(actions_network, "_detect_ssh_ports", return_value=[22]):
            plan = actions_network._build_docker_user_isolation()
            assert plan["validate_commands"] == [["ufw", "status"]]

    def test_docker_user_risky_remote_flag(self):
        """Docker-User actions should be flagged as risky_remote."""
        plan = actions_network._build_docker_user_isolation()
        assert plan["risky_remote"] is True

    def test_docker_user_precondition_callable(self):
        """Docker-User actions should have a precondition callable."""
        plan = actions_network._build_docker_user_isolation()
        assert callable(plan["precondition"])


class TestPlanDeterminism:
    def test_ssh_plan_deterministic(self):
        """SSH plans should be deterministic."""
        with patch.object(actions_ssh, "_find_authorized_keys", return_value=True):
            plan1 = actions_ssh._build_ssh_plan("PasswordAuthentication", "no", lockout_check=True, lockout_value="no")
            plan2 = actions_ssh._build_ssh_plan("PasswordAuthentication", "no", lockout_check=True, lockout_value="no")
            assert plan1["file_changes"] == plan2["file_changes"]
            assert plan1["commands"] == plan2["commands"]
            assert plan1["blockers"] == plan2["blockers"]

    def test_network_plan_deterministic(self):
        """Network plans should be deterministic."""
        with patch.object(actions_network, "_detect_ssh_ports", return_value=[22]):
            plan1 = actions_network._build_ufw_baseline()
            plan2 = actions_network._build_ufw_baseline()
            assert plan1["file_changes"] == plan2["file_changes"]
            assert plan1["commands"] == plan2["commands"]
            assert plan1["blockers"] == plan2["blockers"]
