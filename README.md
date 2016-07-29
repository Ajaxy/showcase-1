# Install and run

1. Navigate to project root path
2. Run `npm i`
3. Run `npm run start`

# Lazy loading
Lazy loading of spots is made in a primitive way. Each time map bounds is changed (map has been moved or zoomed), a socket.io-request is made to a server. Bunch of received spots are being compared to existing ones and if there is something new, spots are re-rendered.

This may be optimized in different ways:
- Using tile-based loader: map view is split to a number of small square "tiles" and separate request is made for each tile. This enables use of browser cache.
- Using complex multi-polygon area as sum of loaded bounds and subtract it out of current bounds before making request.
- Using [ArcGIS Map Service](http://server.arcgis.com/en/server/latest/publish-services/windows/what-is-a-map-service.htm) or [ArcGIS Feature Service](http://server.arcgis.com/en/server/latest/publish-services/windows/what-is-a-feature-service-.htm).
- Using another cartographical API (i.e. [Yandex.Maps Remote Object Manager](https://tech.yandex.com/maps/doc/jsapi/2.1/dg/concepts/remote-object-manager/about-docpage/)).
