{ config, ... }:

let
  rmailPort = 8025;
in {
  networking.firewall.allowedTCPPorts = [ rmailPort ];

  systemd.services.rmail = {
    description = "rmail messaging daemon";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "ritz";
      Group = "users";
      ExecStart = "/etc/profiles/per-user/ritz/bin/luajit /home/ritz/programs/email/rmail.lua";
      Restart = "on-failure";
      RestartSec = 5;
    };
  };
}
