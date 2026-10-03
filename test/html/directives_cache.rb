# Rewrite phase hook that answers with a fixed body. The cases in
# test/t/cases/directives.rb replace cache-v1 in this file with cache-v2
# while nginx runs, and write the original text back afterwards.
Nginx.rputs "cache-v1"
Nginx.return Nginx::HTTP_OK
