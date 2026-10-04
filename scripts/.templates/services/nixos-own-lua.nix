{ config, ... }:
# rmail NixOS service for the mailbox at @MAILBOX@
# Logs to RAM-backed /tmp. One service per mailbox; the name carries the
# mailbox path so a second mailbox adds a service rather than replacing this.

let
  rmailPort = @PORT@;
in {
  networking.firewall.allowedTCPPorts = [ rmailPort ];

  systemd.services."@SERVICE@" = {
    description = "rmail messaging daemon (@MAILBOX@)";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "@USER@";
      Group = "users";
      ExecStart = "@LUA_BIN@ @ROOT@/rmail.lua @CONFIG_FILE@";
      Restart = "on-failure";
      RestartSec = 5;
      StandardOutput = "append:@SERVICE_LOG@";
      StandardError = "append:@SERVICE_LOG@";
    };
  };
}
