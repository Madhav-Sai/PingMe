# Homebrew formula template. Publish a release tag, then fill in url/sha256:
#   curl -L https://github.com/Madhav-Sai/PingMe/archive/refs/tags/v3.3.0.tar.gz | shasum -a 256
class Pingme < Formula
  desc "Fast, fail-closed ICMP/TCP host discovery with hostnames and change tracking"
  homepage "https://github.com/Madhav-Sai/PingMe"
  url "https://github.com/Madhav-Sai/PingMe/archive/refs/tags/v3.3.0.tar.gz"
  sha256 "REPLACE_WITH_RELEASE_SHA256"
  license "MIT"

  depends_on "python@3.12"
  depends_on "fping" => :recommended

  def install
    libexec.install "pingme.py"
    (bin/"pingme").write <<~SH
      #!/bin/sh
      exec "#{Formula["python@3.12"].opt_bin}/python3.12" "#{libexec}/pingme.py" "$@"
    SH
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pingme --version")
    assert_match "REACHABLE", shell_output("#{bin}/pingme 127.0.0.1 --compact --no-history --exit-zero")
  end
end
