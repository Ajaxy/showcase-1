# Demo
http://showcase-1.zinchuk.com:8080/

# Install and run

1. Navigate to project root path
2. Run `npm i`
3. Run `npm run start`

*Note. Make sure that you have MongoDB installed and running.*

# Screenshot
<img src="http://chatik.ajaxy.ru/uploads/showcase-1-1469821646618.png" width="405" /> 

# Libs and Technologies
**Express.js** is server-side **Node.js** framework running along with **MongoDB** as NoSQL database. **Mongoose** is used as ORM layer for manipulating database documents. Server-side app is connected with client via **WebSockets** with help of **socket.io**.

Client-side is a SPA with **immutable** app state stored in **Redux Store**. State is managed by action creators and reducer. **React** is used as presentation layer framework.

Geographical map is created and managed by **ArcGIS JS API**.

**Mocha** is used as a BDD framework to describe specifications along with **chai** testing utilities.

Project is written in **JavaScript** with benefits of **ECMAScript 6** standard provided by **Babel**. **Webpack** is used as project bundler along with server middleware dev tools such as **React Hot Loader** and **hot module replacement**.

Styles are preprocessed by **Less**.

# Lazy loading
Lazy loading of spots is made in a primitive way. Each time map bounds is changed (map has been moved or zoomed), a socket.io-request is made to a server. Bunch of received spots are being compared to existing ones and if there is something new, spots are re-rendered.

This may be optimized in different ways:
- Using tile-based loader: map view is split into a number of small square "tiles" and separate request is made for each tile. This enables use of browser cache.
- Using complex multi-polygon area as sum of loaded bounds and subtract it out of current bounds before making request.
- Using [ArcGIS Map Service](http://server.arcgis.com/en/server/latest/publish-services/windows/what-is-a-map-service.htm) or [ArcGIS Feature Service](http://server.arcgis.com/en/server/latest/publish-services/windows/what-is-a-feature-service-.htm).
- Using another cartographical API (i.e. [Yandex.Maps Remote Object Manager](https://tech.yandex.com/maps/doc/jsapi/2.1/dg/concepts/remote-object-manager/about-docpage/)).
