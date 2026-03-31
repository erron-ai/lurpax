class Lurpax < Formula
  desc "Encrypted snapshot vault CLI — zstd + XChaCha20-Poly1305 + Reed-Solomon"
  homepage "https://github.com/erron-ai/lurpax"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_intel do
      url "https://github.com/erron-ai/lurpax/releases/download/v#{version}/lurpax-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AFTER_RELEASE"
    end

    on_arm do
      url "https://github.com/erron-ai/lurpax/releases/download/v#{version}/lurpax-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AFTER_RELEASE"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/erron-ai/lurpax/releases/download/v#{version}/lurpax-v#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AFTER_RELEASE"
    end

    on_arm do
      url "https://github.com/erron-ai/lurpax/releases/download/v#{version}/lurpax-v#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AFTER_RELEASE"
    end
  end

  def install
    bin.install "lurpax"
  end

  test do
    assert_match "lurpax", shell_output("#{bin}/lurpax --help")
  end
end
