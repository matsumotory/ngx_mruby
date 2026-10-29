# Lifetimes

nginx creates one `mrb_state` for the `http {}` block, and one for the
`stream {}` block, while it reads the configuration. Each worker process
gets its own copy when nginx forks it, and runs the Ruby code of every
request of that worker in it. The state is not created per request, so
what one request leaves in it, the next request of the worker sees.

```diagram
worker-lifetime
caption: The `mrb_state` of the `http {}` block, from the configuration to the end of a worker.
source: src/http/ngx_http_mruby_module.c 575-598 600-632 727-730 1136-1142 1282-1300 1421-1450
at: 0c72e3970 2026-10-19
open: In the master process, `mrb_open` creates the `mrb_state`; while nginx reads the directives, it compiles their code and runs the server context code; then `mruby_init` runs
fork: nginx starts the workers: each worker has its own copy of the `mrb_state`
init-worker: The worker runs `mruby_init_worker`
requests: Every request of the worker runs its handlers and filters in that `mrb_state`; global variables, constants, methods and classes stay, and ngx_mruby clears only the exception (`mrb->exc`) after each run
exit-worker: The worker stops and runs `mruby_exit_worker`
```

## What a worker keeps between requests

nginx creates one `mrb_state` for the `http {}` block (and one for the `stream {}` block) while it reads the configuration, and runs the init code (`mruby_init`, `mruby_stream_init`) and the server configuration code (`mruby_server_context_handler_code`) in it before it starts the workers, in the master process. Each worker process gets its own copy when nginx forks it, and runs all the other mruby code of the block in that copy: the init_worker and exit_worker code and every handler and filter, in every server and location, for every client. A reload or a restart starts new workers with a new state.

Global variables, constants, instance variables of `main` (the `self` of handler code), methods defined with `def`, classes and modules with their constants, and what `Userdata` holds (it keeps its values in a global variable) stay in the worker from one request to the next. What one request leaves behind is seen by every later request that the same worker handles, also when the code raised an exception after it made the change. Each worker has its own copy, so one worker does not see the values of another. After each run, ngx_mruby clears the exception (`mrb->exc`); a script file without `cache` is read and compiled again for the next run, and inline code and cached scripts keep the byte-code compiled at startup. The garbage collector frees the objects that nothing refers to any more. Local variables do not stay: each run of handler code starts without them.

Do not keep the data of one request in global variables, constants, instance variables of `main` or `Userdata`, since the next request of the worker, from any client, sees it. Use local variables, and read and write the request through `Nginx::Request`, `Nginx::Var`, `Nginx::Headers_in` and `Nginx::Headers_out` (in `stream {}`, where code runs per session, `Nginx::Stream::Connection`). To pass data from one handler to a later handler of the same request, declare an nginx variable with `set $name "";` and read and write it through `Nginx::Var`, or set the `Userdata` value in every request before it is read. A `set` in the location runs after `mruby_rewrite_handler` and empties the variable again, so declare a variable that a rewrite handler writes with `set` in the `server {}` block. Keep in globals and constants only what all requests of the worker are meant to share, such as settings that the init or init_worker code prepares. [`Nginx.remove_global_variable`](../class_and_method/README.md#nginxremove_global_variable) removes a global variable.

The Ruby code of the `stream {}` block runs in the same way in its own
`mrb_state`, with `mruby_stream_init`, `mruby_stream_init_worker`, the
code of each session, and `mruby_stream_exit_worker`.
