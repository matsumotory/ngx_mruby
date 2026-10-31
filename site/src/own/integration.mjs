import { fileURLToPath } from 'node:url';
import { createIndex } from 'pagefind';
export default function ownShell() {
  return {name:'ngx-mruby-own-shell',hooks:{
    'astro:config:setup':({injectRoute})=>{
      injectRoute({pattern:'[...slug]',entrypoint:fileURLToPath(new URL('./Route.astro',import.meta.url)),prerender:true});
      injectRoute({pattern:'404',entrypoint:fileURLToPath(new URL('./NotFound.astro',import.meta.url)),prerender:true});
    },
    'astro:build:done':async({dir})=>{
      const { index, errors }=await createIndex({});
      if(errors.length)throw new Error(errors.join('\n'));
      const result=await index.addDirectory({path:fileURLToPath(dir)});
      if(result.errors.length)throw new Error(result.errors.join('\n'));
      const written=await index.writeFiles({outputPath:fileURLToPath(new URL('pagefind/',dir))});
      if(written.errors.length)throw new Error(written.errors.join('\n'));
      await index.deleteIndex();
    }
  }};
}
