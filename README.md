<div align="center">
  <img src="src/wisp-logo.svg" alt="Light Wisp Server" width="200" height="200" />
  <h1>Bare Js Wisp Server</h1>
  <p>Exactly what it is, a Light Wisp Server (No Node.js, Just pure JS and Cloudflare Workers via V8) Somewhat based on Wisp Js</p>

  <h2>Deploy</h2>
  <p>Use the Button Below to Deploy To Cloudflare</p>
  <br />

  [![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/sriail/Bare-Js-Wisp-Server)
  <br />

  <h2>Stability and Notes On TCP</h2>
  <p>From what I know, the proxy is very stable. However, Cloudflare can limit the number of request (occasionally subrequest) to 50 for Non-Premium Accounts, and does not support TCP (Meaning only UDP request get fully proxied) which is a Huge issue which i will hopefully patch with some Janky solution which i am adding.</p>
  <br />

  <h2>Quick Roadmap</h2>
</div>

<div align="center">
<div align="left" style="display: inline-block;">

- [x] Add TCP support (grab tcp in some other way and send it out as alt udp streams to the client, or just wait for them to add it natively???)
- [x] Add Domain Mirroring ( Can access on alt Cloudflare domains for the worker, may already work?)
- [x] Add Rate Limiting in editable JS File. (WIP)
- [ ] Wisp v2.1??? (to lazy to add rn)
- [ ] Add Implamentation.md and a proper Client
- [ ] Add Plugins for JSON, CSV input and output, Web Crawling, and LLM saerch

<div align="center">
  <h2>Notes</h2>
  <p>Because of Cloudflare places a 100,000 request restricton on the connect() Api, the endpoint will not be able to handle tons of trafic daily without the premum subscription
  (Which hase a limit of 10,000,000 daily request) so it is recomended to host on your owen hardware if possable for maximum preformance.</p>
  <br />

</div>
</div>
</div>
