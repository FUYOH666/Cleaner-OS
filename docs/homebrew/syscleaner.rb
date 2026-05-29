# Homebrew formula (example — use after PyPI publish)
# brew install --formula docs/homebrew/syscleaner.rb
# Or publish to homebrew-core / personal tap

class Syscleaner < Formula
  include Language::Python::Virtualenv

  desc "Trusted audit and tiered cleanup for dev workstations"
  homepage "https://github.com/FUYOH666/Cleaner-OS"
  url "https://pypi.org/packages/source/s/syscleaner/syscleaner-1.2.0.tar.gz"
  sha256 "SKIP"
  license "MIT"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/syscleaner", "health"
  end
end
