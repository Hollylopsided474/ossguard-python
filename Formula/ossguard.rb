class Ossguard < Formula
  desc "One CLI to guard any OSS project with OpenSSF security best practices"
  homepage "https://github.com/kirankotari/ossguard"
  url "https://github.com/kirankotari/ossguard/archive/refs/tags/v0.1.0.tar.gz"
  license "Apache-2.0"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "ossguard", shell_output("#{bin}/ossguard version")
  end
end
