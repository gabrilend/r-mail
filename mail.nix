# NixOS module for rmail.
# Import this from your configuration.nix.

{ config, pkgs, ... }:

let
  luaEnv = pkgs.lua5_4.withPackages (ps: [ ps.luasocket ]);
in {
  networking.firewall.allowedTCPPorts = [ 8025 ];

  systemd.services.rmail = {
    description = "rmail messaging daemon";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "ritz";
      Group = "users";
      ExecStart = "${luaEnv}/bin/lua /home/ritz/programs/email/rmail.lua";
      Restart = "on-failure";
      RestartSec = 5;
    };
  };
}
