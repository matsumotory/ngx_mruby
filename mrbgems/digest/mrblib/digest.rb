# The methods of Digest that src/digest.c does not define. Together they keep
# the API of iij/mruby-digest, which the default build of ngx_mruby 2.x had.
module Digest
  class Base
    def self.digest(data)
      new.update(data).digest
    end

    def self.hexdigest(data)
      new.update(data).hexdigest
    end

    # Reads the whole file in the worker, when a script calls it.
    def self.file(path)
      new.file(path)
    end

    def file(path)
      update(File.open(path, 'rb') { |f| f.read } || '')
    end

    def ==(other)
      if other.kind_of?(String)
        hexdigest == other
      else
        digest == other.digest
      end
    end

    def hexdigest!
      s = hexdigest
      reset
      s
    end

    alias length digest_length
    alias size digest_length
    alias to_s hexdigest
    alias << update
  end

  class HMAC
    def self.digest(data, key, digest)
      new(key, digest).update(data).digest
    end

    def self.hexdigest(data, key, digest)
      new(key, digest).update(data).hexdigest
    end

    alias << update
  end
end
