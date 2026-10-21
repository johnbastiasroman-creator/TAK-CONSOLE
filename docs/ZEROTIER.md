# ZeroTier local

## Qué se despliega

Un **controlador ZeroTier propio** en este equipo, administrado con **ZTNET**. El controlador decide qué nodos entran a cada red, qué IP reciben y qué reglas de tráfico aplican. Ya no dependes de ZeroTier Central (my.zerotier.com) para administrar tus redes.

El mismo contenedor `zerotier` es además el nodo de este servidor: al unirte a una red se crea una interfaz `zt*` en el equipo, y TAK Server, MediaMTX y Mumble quedan accesibles por su IP ZeroTier.

## Raíces: públicas o privadas

Un controlador no basta para que los nodos se encuentren. Para atravesar NAT, los nodos usan **raíces** (servidores "planet"):

| Modo | Cómo funciona | A favor | En contra |
|---|---|---|---|
| **Raíces públicas** (por defecto) | Los nodos se encuentran a través de las raíces de ZeroTier Inc. | Funciona con las apps oficiales de Android, iOS, Windows, macOS y Linux. Sin infraestructura extra. | Requiere internet para el descubrimiento; dependes de las raíces de ZeroTier Inc. (tu tráfico va cifrado de extremo a extremo). |
| **Raíz privada** (planet propio) | Generas un archivo `planet` con tus propias raíces y lo distribuyes a cada nodo. | Independiente de ZeroTier Inc. Puede funcionar en una red aislada con IPs internas. | Las apps oficiales de **Android e iOS no aceptan planets personalizados**; hay forks no oficiales (ZerotierFix, ZeroTieriOSFix), con sus propios riesgos. Cada cliente necesita el archivo. |

Para equipos ATAK en Android con la app oficial de ZeroTier, mantén las **raíces públicas**.

### Usar una raíz privada

1. En ZTNET: *Admin → Controller → Generate Planet*. Indica `IP:9993` del equipo que hará de raíz. Puede ser tu servidor con IP pública estática, si también corre ZeroTier con el puerto 9993/udp abierto. Para un sitio aislado, usa IPs internas.
2. ZTNET instala el planet en el controlador. En la consola, pulsa **Reiniciar nodo ZeroTier**.
3. Verifica en la página del módulo que el *modo actual* diga "Raíz privada" y que aparezcan tus raíces.
4. Distribuye el archivo (botón **Descargar planet actual**, o `https://<ztnet>:3443/api/planet`) a cada cliente:
   - Linux: `/var/lib/zerotier-one/planet`, luego `sudo systemctl restart zerotier-one`
   - Windows: `%PROGRAMDATA%\ZeroTier\One\planet`, luego reinicia el servicio ZeroTier One

También puedes **subir** un planet generado en otro lugar (por ejemplo con `mkworld`) y **restaurar las raíces públicas** cuando quieras. El planet anterior siempre queda respaldado en `data/stacks/zerotier/zerotier-one/planet.bak-*`.

## Por qué ZeroTier 1.14.2

Revisado en el código fuente oficial (github.com/zerotier/ZeroTierOne):

- **1.14.2** y anteriores: *Business Source License 1.1*. La 1.14.2 declara `Change Date: 2026-01-01` y `Change License: Apache License version 2.0`. Antes de esa fecha, su "Additional Use Grant" prohibía, entre otros, el uso "in a government setting in support of any active government function or operation".
- **1.16.x**: el agente (nodo) usa MPL-2.0, pero el **controlador** está en `nonfree/` bajo la *ZeroTier Source-Available License*, que solo permite uso no comercial y cuenta como comercial "any use of the Software by or for the benefit of a government or military entity".

Como el controlador es justamente lo que esta consola despliega, la imagen queda fijada en `zyclonite/zerotier:1.14.2`. No la actualices a 1.16 o superior sin revisar esa licencia. Esto no es asesoría legal; si el despliegue es para un cliente gubernamental o de defensa, confírmalo con tu área legal.

## Seguridad de ZTNET

- ZTNET escucha solo en `127.0.0.1:3000`; el acceso es por HTTPS en `:3443` (Caddy con el certificado de la consola).
- **El primer usuario que se registra queda como administrador.** Créalo apenas termine el despliegue y luego desactiva el registro de nuevos usuarios en ZTNET.
- ZTNET solo acepta inicios de sesión desde la dirección elegida al desplegar (`NEXTAUTH_URL`). Si cambias de IP, vuelve a desplegar el módulo con la nueva dirección.
- La política de exposición de *Red y firewall* también se aplica al puerto 3443.
