t = SimpleTest.new "ngx_mruby test: Dir of the core gem mruby-dir (test/conf/conf.d/62-gem-dir.conf)"

GEM_DIR_PORT = 18127

t.assert('mruby-dir', 'Dir lists, reads and closes test/html/gem_dir from a handler') do
  res = HttpRequest.new.get base(GEM_DIR_PORT) + '/gem_dir'
  t.assert_equal 200, res.code
  t.assert_equal [
    "true,false,false",     # Dir.exist? of the directory, a missing name and a file
    ".,..,one.txt,two.txt", # Dir.entries
    ".,..,one.txt,two.txt", # Dir#read until nil, then Dir#close
    "IOError",              # Dir#read of the closed Dir
    "IOError",              # Dir#close of the closed Dir
    "block value",          # Dir.open with a block that closed the Dir
    "one.txt,two.txt",      # Enumerable#select on a Dir
    ".,..,one.txt,two.txt", # Dir.children (in mruby 3.3.0 an alias of Dir.entries)
    ".,..,one.txt,two.txt", # Dir#each_child (in mruby 3.3.0 an alias of Dir#each)
    "false",                # Dir.empty? of the directory
    "0",                    # file descriptors that Dir.foreach left open (its Dir is closed)
  ], res["body"].split("\n")
end

t.report
