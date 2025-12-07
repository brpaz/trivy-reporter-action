{
  pkgs,
  lib,
  config,
  inputs,
  ...
}: {
  dotenv.enable = true;

  languages.javascript = {
    enable = true;
    package = pkgs.nodejs_24;
    corepack = {
      enable = true;
    };
    pnpm = {
      enable = true;
      package = pkgs.pnpm;
    };
  };

  # https://devenv.sh/packages/
  packages = with pkgs; [
    actionlint
  ];

  # https://devenv.sh/scripts/
  scripts.install_deps.exec = ''
    echo "📦 Installing dependencies"
    pnpm install
  '';

  enterShell = ''
    install_deps
  '';

  # https://devenv.sh/tasks/
  # tasks = {
  #   "myproj:setup".exec = "mytool build";
  #   "devenv:enterShell".after = [ "myproj:setup" ];
  # };

  # https://devenv.sh/tests/
  enterTest = ''
    echo "Running tests..."
    pnpm test
  '';

  # https://devenv.sh/git-hooks/
  # git-hooks.hooks.shellcheck.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
