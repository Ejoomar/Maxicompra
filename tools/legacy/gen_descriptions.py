#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generador de descripciones LARGAS para productos Maxicompra.
Cada descripcion tiene 10+ lineas / ~250 palabras.
No usa LLM — cero tokens de inferencia.
"""

import json, re

def extract_specs(name):
    n = name.lower()
    s = {}
    m = re.search(r'(\d[\d.,]*)\s*mah', n)
    if m: s['mah'] = m.group(1).replace(',','.')
    m = re.search(r'(\d[\d.,]*)\s*w\b', n)
    if m: s['watts'] = m.group(1)
    m = re.search(r'(\d+)\s*(tb|gb)\b(?!\s*ram)', n)
    if m: s['storage'] = f"{m.group(1)}{m.group(2).upper()}"
    m = re.search(r'(\d+)\s*gb\s*ram', n)
    if m: s['ram'] = f"{m.group(1)}GB"
    m = re.search(r'(\d+)\s*(pilas|unidades|piezas|pares|pack|tomas)\b', n)
    if m: s['pack'] = m.group(1)
    if re.search(r'bluetooth|inalambrico|wireless', n): s['bt'] = True
    if re.search(r'usb.?c|type.?c', n): s['usbc'] = True
    m = re.search(r'ipx?(\d+)', n)
    if m: s['ip'] = f"IP{m.group(1)}"
    m = re.search(r'clase\s*(\d+)', n)
    if m: s['clase'] = m.group(1)
    m = re.search(r'(\d+)\s*kg\b', n)
    if m: s['kg'] = m.group(1)
    m = re.search(r'(\d+)\s*litros?\b', n)
    if m: s['litros'] = m.group(1)
    for c in ['negro','blanco','rojo','azul','verde','plateado','gris','dorado','rosa','naranja']:
        if c in n: s['color'] = c.capitalize(); break
    return s

def bp(brand):
    b = (brand or '').strip()
    return f"{b} " if b else ""

def generate_desc(p):
    name  = p.get('name', '').strip()
    brand = p.get('brand', '') or ''
    cat   = p.get('cat', '')
    n     = name.lower()
    s     = extract_specs(name)
    B     = bp(brand)

    # ── AUDIO ────────────────────────────────────────────────────────────────
    if cat == 'Audio':

        if re.search(r'auricular|headphone|earphone|in-ear|over-ear|tws', n):
            ip_txt = f" La certificacion {s['ip']} garantiza resistencia al agua y sudor para sesiones de entrenamiento intensas." if s.get('ip') else ""
            if s.get('bt') or re.search(r'inalambrico|wireless', n):
                return (
                    f"Los auriculares {B}inalambricos representan la opcion ideal para quienes buscan libertad de movimiento sin sacrificar la calidad de sonido.\n\n"
                    f"Gracias a su conexion Bluetooth de ultima generacion, el emparejamiento con tu smartphone, tablet o computador es instantaneo y la senal se mantiene estable incluso en espacios con mucha interferencia.\n\n"
                    f"El diseno in-ear se ajusta perfectamente al canal auditivo, proporcionando un sello acustico natural que reduce el ruido del entorno sin necesidad de cancelacion activa.{ip_txt}\n\n"
                    f"La calidad de audio destaca por sus graves profundos, medios equilibrados y agudos nítidos, ofreciendo una experiencia sonora que supera expectativas en su rango de precio.\n\n"
                    f"La bateria de larga duracion permite sesiones de escucha extendidas sin interrupciones, y cuando se agota, el estuche de carga te da recargas adicionales mientras vas en movimiento.\n\n"
                    f"Son perfectos para entrenamiento en el gimnasio, salir a correr, viajes en transporte publico o simplemente disfrutar musica en casa sin enredos de cable.\n\n"
                    f"El microfono integrado los convierte ademas en unos auriculares manos libres completos, ideales para atender llamadas con claridad o participar en videollamadas de trabajo.\n\n"
                    f"Compatibles con iOS y Android, funcionan con cualquier dispositivo que tenga Bluetooth. Incluyen diferentes tamanos de almohadillas para adaptarse a cualquier tamano de oído.\n\n"
                    f"Despacho rapido a todo Chile con garantia incluida."
                )
            return (
                f"Los auriculares {B}con cable ofrecen una experiencia de audio confiable y de alta fidelidad para el uso diario.\n\n"
                f"Su construccion robusta y el cable reforzado en los extremos los hacen resistentes al uso intensivo, ya sea en casa, la oficina o durante el estudio.\n\n"
                f"La respuesta de frecuencia amplia garantiza una reproduccion precisa de todos los rangos sonoros: desde los bajos profundos hasta los detalles mas finos de los agudos.\n\n"
                f"Las almohadillas de espuma de memoria se adaptan a la forma de tu oido, distribuyendo la presion de manera uniforme para que puedas usarlos horas seguidas sin molestias.\n\n"
                f"El microfono integrado en el cable permite atender llamadas sin quitartelos, con captacion clara de voz y reduccion basica de ruido ambiental.\n\n"
                f"El conector jack de 3.5mm es universal: funciona con smartphones, tablets, notebooks, consolas de videojuegos y cualquier equipo de audio con entrada estandar.\n\n"
                f"Son especialmente valorados por quienes prefieren una conexion cableada para mayor fidelidad de sonido sin preocuparse de bateria ni emparejamientos.\n\n"
                f"Livianos y plegables, caben facilmente en cualquier bolso o mochila. Incluyen estuche de transporte para protegerlos cuando no los usas.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'parlante|speaker|altavoz|bocina', n):
            if 'karaoke' in n:
                return (
                    f"El parlante karaoke {B}es el complemento perfecto para animar cualquier reunion familiar, fiesta infantil o celebracion en casa.\n\n"
                    f"Viene con microfono incluido listo para usar, luces LED multicolor que se sincronizan con el ritmo de la musica y un sonido potente que llena cualquier ambiente.\n\n"
                    f"La conexion Bluetooth te permite enlazarlo a tu smartphone o tablet en segundos para reproducir las pistas de karaoke de YouTube, Spotify o cualquier app de musica.\n\n"
                    f"Tambien cuenta con entrada auxiliar de 3.5mm y puerto USB para conectar reproductores MP3 o dispositivos sin Bluetooth, garantizando compatibilidad total.\n\n"
                    f"Su construccion resistente esta disenada para soportar el uso continuo en fiestas y eventos: carcasa reforzada que aguanta golpes y la vibración del volumen alto.\n\n"
                    f"Los controles de volumen, eco y balance vocal estan al alcance de la mano para ajustar el sonido en tiempo real sin interrumpir la fiesta.\n\n"
                    f"La bateria recargable incorporada permite usarlo sin cables por horas, ideal para terraza, patio o salon sin depender de un enchufe cercano.\n\n"
                    f"Perfecto como regalo para ninos y adolescentes: llega listo para usar con todo incluido en la caja, sin necesidad de accesorios adicionales.\n\n"
                    f"Despacho rapido a todo Chile con garantia incluida."
                )
            if s.get('bt') or re.search(r'portatil|portable|inalambrico', n):
                return (
                    f"El parlante portatil {B}con Bluetooth redefine lo que se puede esperar de un equipo de audio compacto para el uso diario.\n\n"
                    f"Su conexion inalambrica estable permite disfrutar musica desde el celular, tablet o computador hasta varios metros de distancia sin perder calidad de audio.\n\n"
                    f"El sonido sorprende por la profundidad de sus graves y la claridad de los medios, logrando un volumen que llena habitaciones sin distorsion a maxima potencia.\n\n"
                    f"La bateria de larga duracion aguanta horas de reproduccion continua con una sola carga, lo que lo hace ideal para picnic, playa, terraza o dia de campo.\n\n"
                    f"El diseno compacto y liviano permite llevarlo en cualquier bolso sin ocupar espacio, y su carcasa resistente soporta los golpes tipicos del uso exterior.\n\n"
                    f"Muchos modelos incluyen microfono incorporado para funcionar como manos libres durante llamadas, manteniendo la conversacion clara desde cualquier lugar de la habitacion.\n\n"
                    f"La carga se realiza via USB-C o Micro-USB segun el modelo, compatible con los mismos cables que ya tienes en casa, sin necesidad de adaptadores especiales.\n\n"
                    f"Ideal como regalo o para complementar el setup de musica del hogar, la oficina o los espacios donde el enchufe no siempre esta cerca.\n\n"
                    f"Despacho rapido a todo Chile con garantia incluida."
                )
            return (
                f"El parlante {B}para el hogar ofrece una experiencia de audio superior gracias a sus drivers de alta eficiencia y caja acustica disenada para maximizar la reproduccion sonora.\n\n"
                f"Los bajos son profundos y bien controlados, los medios estan equilibrados con claridad vocal excepcional y los agudos se reproducen sin la dureza tipica de equipos de menor calidad.\n\n"
                f"La conectividad multiple incluye Bluetooth, entrada auxiliar 3.5mm y puerto USB, permitiendo conectar cualquier dispositivo sin importar si es nuevo o antiguo.\n\n"
                f"El control de volumen accesible y los indicadores LED discretos hacen que la operacion sea intuitiva para cualquier miembro de la familia, sin importar la edad.\n\n"
                f"Su construccion solida con materiales de alta resistencia garantiza que mantendra su rendimiento y apariencia durante anos de uso cotidiano intensivo.\n\n"
                f"El tamano es ideal para colocarlo en el living, la habitacion, la cocina o la oficina: suficientemente pequeno para no ocupar espacio pero con la potencia para sonar a buen volumen.\n\n"
                f"Perfecto para escuchar musica mientras cocinas, trabajas desde casa, recibes amigos o simplemente te relajas. La calidad de audio marca una diferencia real en el dia a dia.\n\n"
                f"Incluye cable de alimentacion y manual de usuario. Garantia valida en Chile.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'microfono|microfono|mic\b', n):
            return (
                f"El microfono {B}esta disenado para quienes exigen claridad de voz en grabaciones, streaming, videollamadas y podcasting desde casa o la oficina.\n\n"
                f"El patron de captacion cardioide recoge el sonido directamente al frente mientras rechaza el ruido lateral y posterior, resultando en una voz limpia y profesional.\n\n"
                f"La conexion USB plug & play elimina la necesidad de interfaces de audio o drivers adicionales: simplemente conecta y empieza a grabar en segundos en cualquier PC o Mac.\n\n"
                f"El diafragma de alta sensibilidad capta todos los matices de la voz, desde los susurros mas suaves hasta los tonos mas fuertes, sin saturacion ni distorsion.\n\n"
                f"La base antivibratoria integrada aísla el microfono de las vibraciones de la mesa como golpes accidentales o la vibración de parlantes cercanos, manteniendo el audio limpio.\n\n"
                f"Compatible con las principales plataformas de streaming, software de grabacion, clientes de videollamadas como Zoom y Teams, y sistemas operativos Windows, macOS y Linux.\n\n"
                f"Ideal para content creators, podcasters, profesores de clases online, gamers y cualquier persona que necesite audio de calidad superior al del microfono del portatil.\n\n"
                f"El diseno compacto permite posicionarlo en cualquier escritorio sin quitarle espacio a lo que importa. Incluye cable USB y base ajustable en angulo.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback audio
        return (
            f"Dispositivo de audio {B}disenado para quienes valoran la calidad sonora en su vida diaria.\n\n"
            f"Sus componentes internos garantizan una reproduccion fiel que respeta la intencion original de cada pieza musical, podcast o contenido de audio.\n\n"
            f"La construccion cuidada con materiales seleccionados se refleja en una durabilidad superior a la de productos de menor precio en el mismo segmento.\n\n"
            f"La compatibilidad universal con smartphones, tablets, notebooks y reproductores de audio lo convierte en un accesorio versatil para cualquier situacion.\n\n"
            f"El diseno ergonomico reduce la fatiga en sesiones largas, pensado para quienes pasan mucho tiempo escuchando musica, estudiando o trabajando con audio.\n\n"
            f"Facil de configurar y usar desde el primer momento: sin aplicaciones requeridas, sin configuraciones complejas, funciona out of the box.\n\n"
            f"Una adicion solida a tu setup de audio que notaras desde la primera vez que lo uses, tanto en calidad de sonido como en comodidad de uso.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── ELECTRONICA ──────────────────────────────────────────────────────────
    if cat == 'Electronica' or cat == 'Electrónica':

        if re.search(r'power.?bank|bateria ext|batería ext|cargador portatil', n):
            mah = f"de {s['mah']} mAh " if s.get('mah') else ""
            w   = f"con tecnologia de carga rapida de {s['watts']} W " if s.get('watts') else ""
            return (
                f"La bateria externa {B}{mah}{w}es la solucion definitiva para quienes necesitan autonomia total sin depender de enchufes durante el dia.\n\n"
                f"Su capacidad permite recargar multiples veces un smartphone moderno, mantener los audífonos TWS funcionando y ademas cargar una tablet o camara antes de necesitar recargarse ella misma.\n\n"
                f"La tecnologia de carga rapida reduce significativamente el tiempo de espera comparado con cargadores convencionales, fundamental cuando cada minuto cuenta.\n\n"
                f"Cuenta con multiples puertos de salida USB-A y USB-C para cargar dos dispositivos al mismo tiempo, eliminando la necesidad de elegir cual equipo cargaar primero.\n\n"
                f"El diseno compacto y liviano facilita llevarlo en cualquier bolso o mochila sin que se sienta como un peso extra, ideal para viajes, jornadas laborales largas o dias de campo.\n\n"
                f"Los circuitos de proteccion integrados monitorizan la temperatura, voltaje y corriente en tiempo real, protegiendo tanto la bateria externa como los dispositivos conectados de danos.\n\n"
                f"El indicador LED de nivel de carga te mantiene informado del porcentaje disponible con un simple vistazo, sin necesidad de conectarla a ningun dispositivo para verificarlo.\n\n"
                f"Compatible con todos los smartphones Android e iOS actuales, tablets, audífonos, camaras de accion y cualquier dispositivo que cargue via USB.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'\bpila|\bbateria aa|\bbateria aaa|\bbateria d\b|\bbateria c\b', n):
            pack = f"en pack de {s['pack']} unidades " if s.get('pack') else ""
            return (
                f"Las pilas alcalinas {B}{pack}son la opcion de mayor confiabilidad para todos los dispositivos electronicos del hogar que requieren baterias convencionales.\n\n"
                f"Su formulacion de alta densidad energetica garantiza una duracion hasta 10 veces mayor que las pilas de carbono convencionales en el mismo tipo de dispositivo.\n\n"
                f"La tecnologia Power Seal de la celda previene las fugas de electrolito incluso cuando la pila esta completamente descargada, protegiendo tus dispositivos de danos costosos.\n\n"
                f"Funcionan de manera optima en un amplio rango de temperaturas, desde los -20°C del invierno hasta los 54°C de ambientes calurosos, sin perder rendimiento.\n\n"
                f"Son compatibles con todos los dispositivos que usan ese formato: controles remotos de TV, juguetes electronicos, relojes de pared, teclados inalambricos, mouses, linternas y mucho mas.\n\n"
                f"La fecha de vencimiento garantiza hasta 10 anos de vida util en almacenamiento, por lo que comprar en pack grande es siempre una decision economicamente inteligente.\n\n"
                f"El empaque hermetico protege las pilas de la humedad ambiental durante el almacenamiento, manteniendo la carga completa hasta el momento en que las necesitas.\n\n"
                f"Una marca de confianza global respaldada por decadas de liderazgo en el mercado de baterias de consumo masivo, disponible ahora en Maxicompra Chile.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'cargador|charger', n) and not re.search(r'power.?bank|inalambrico', n):
            w    = f"de {s['watts']} W " if s.get('watts') else ""
            usbc = "con conector USB-C " if s.get('usbc') else ""
            return (
                f"El cargador {B}{usbc}{w}esta disenado para reponer la bateria de tus dispositivos en el menor tiempo posible sin comprometer la seguridad de los componentes internos.\n\n"
                f"La tecnologia de carga inteligente detecta automaticamente el protocolo de carga rapida compatible con tu dispositivo y entrega la maxima potencia permitida de forma segura.\n\n"
                f"Los circuitos de proteccion multiples previenen sobrecarga, sobrecalentamiento, cortocircuito y fluctuaciones de voltaje que podrian danar la bateria de tu equipo a largo plazo.\n\n"
                f"Su diseno compacto es ideal para viajes: ocupa minimo espacio en la maleta o neceser y el cable compatible suele ser el mismo que ya usas a diario.\n\n"
                f"Compatible con la gran mayoria de smartphones Android con carga rapida Qualcomm Quick Charge, y con dispositivos Apple que soporten carga rapida via USB-C.\n\n"
                f"El acabado termico del cuerpo disipa el calor generado durante la carga, manteniendo una temperatura segura incluso en cargas prolongadas durante la noche.\n\n"
                f"Certificaciones de seguridad internacionales garantizan que cumple con los estandares de calidad y seguridad electrica exigidos en el mercado chileno.\n\n"
                f"Ideal como repuesto del cargador original o para tener uno extra en la oficina, el auto o la mochila de viaje. Compatible con voltaje universal 100-240V.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'cable usb|cable carga|cable tipo|cable lightning|cable micro', n):
            return (
                f"El cable de carga {B}es uno de esos accesorios que marca la diferencia en la experiencia diaria de uso de tus dispositivos, y este modelo esta fabricado para durar.\n\n"
                f"El nylon trenzado de alta resistencia que recubre el cable previene los nudos, la abrasion y el desgaste tipico que aparece en los cables convencionales a los pocos meses de uso.\n\n"
                f"Los conectores metalicos reforzados en ambos extremos resisten miles de ciclos de conexion y desconexion sin que el terminal se afloje ni pierda contacto electrico.\n\n"
                f"Soporta carga rapida en dispositivos compatibles, entregando la maxima corriente que el equipo puede recibir de forma segura para acortar los tiempos de carga.\n\n"
                f"La transmision de datos a alta velocidad lo hace util no solo para cargar sino tambien para sincronizar archivos, fotos y backups entre el celular y el computador.\n\n"
                f"El diseno flexible pero firme mantiene su forma incluso despues de enrollarlo y desenrollarlo repetidamente, sin que se formen las tipicas marcas de doblado.\n\n"
                f"Una longitud generosa permite usar el dispositivo comodamente mientras carga, ya sea desde el enchufe de pared, el computador o la bateria externa.\n\n"
                f"Compatible con todos los cargadores actuales y anteriores que usen el mismo conector, sin necesidad de adaptadores adicionales.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'lampara|led|foco|bombilla|luz', n):
            w = f"de {s['watts']} W " if s.get('watts') else ""
            return (
                f"La luminaria LED {B}{w}representa la evolucion del alumbrado domestico hacia mayor eficiencia energetica sin sacrificar la calidad de luz.\n\n"
                f"Consume hasta un 80% menos de energia que una bombilla incandescente equivalente, lo que se traduce en un ahorro real y visible en la cuenta de luz desde el primer mes.\n\n"
                f"La vida util de hasta 25.000 horas equivale a mas de 10 anos de uso normal, eliminando la necesidad de cambios frecuentes y reduciendo el gasto en reemplazos.\n\n"
                f"La luz uniforme y estable sin parpadeo reduce la fatiga visual en actividades de lectura, trabajo o estudio prolongado comparado con luminarias de menor calidad.\n\n"
                f"La temperatura de color esta cuidadosamente calibrada para crear el ambiente correcto: luz calida para dormitorios y living, o luz fria para cocinas y oficinas segun el modelo.\n\n"
                f"El arranque instantaneo sin tiempo de calentamiento la diferencia de las luces fluorescentes: alcanza su maxima luminosidad desde el primer segundo de encendido.\n\n"
                f"Construccion sin mercurio ni otros materiales toxicos, respetuosa con el medioambiente tanto en su fabricacion como en su disposicion final al fin de su vida util.\n\n"
                f"Compatible con la mayoria de portalamparas estandar, de instalacion directa sin modificaciones en la instalacion electrica existente.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'zapatilla|regleta|alargador|enchufe multiple', n):
            tomas = f"con {s['pack']} tomas " if s.get('pack') else ""
            return (
                f"La zapatilla electrica {B}{tomas}es el accesorio indispensable para cualquier espacio donde la demanda de enchufes supera la oferta disponible en la pared.\n\n"
                f"El protector contra sobretensiones integrado actua como un escudo para todos los equipos conectados, desconectandolos automaticamente si el voltaje supera el nivel seguro.\n\n"
                f"Cada toma acepta clavijas de dos o tres pines en formato chileno, con contacto firme que evita los microcortes de corriente que danan equipos sensibles como computadores y televisores.\n\n"
                f"El cable de longitud generosa permite ubicar la zapatilla donde mas se necesita sin quedar condicionado a la posicion del enchufe de pared mas cercano.\n\n"
                f"Muchos modelos incluyen puertos USB integrados para cargar smartphones y tablets directamente sin ocupar tomas de corriente, maximizando el espacio disponible.\n\n"
                f"El interruptor maestro con luz indicadora permite apagar todos los equipos conectados con un solo movimiento, eliminando el consumo fantasma durante la noche o la ausencia.\n\n"
                f"La carcasa ignifuga de policarbonato resiste temperaturas elevadas sin deformarse ni liberar gases toxicos, cumpliendo con los estandares de seguridad electrica.\n\n"
                f"Ideal para escritorio de trabajo, setup gamer, home theater, cocina o cualquier espacio donde se concentren multiples equipos electronicos.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'\bradio\b|fm.?am|am.?fm', n):
            return (
                f"La radio portatil {B}AM/FM es un clasico que nunca pierde vigencia gracias a su simplicidad, confiabilidad y la capacidad de recibir contenido en tiempo real sin depender de internet.\n\n"
                f"La antena telescopica ajustable permite optimizar la recepcion segun la ubicacion, captando emisoras con claridad incluso en zonas con senal debil o irregular.\n\n"
                f"El dial de sintonizacion manual da un control preciso para encontrar exactamente la frecuencia deseada, con el placer tactico de explorar el espectro radial libremente.\n\n"
                f"Funciona con pilas estandar que consigue en cualquier tienda, garantizando autonomia total incluso durante cortes de luz, viajes a zonas remotas o emergencias.\n\n"
                f"El parlante integrado produce un sonido sorprendentemente claro y bien equilibrado para el tamano del equipo, con volumen suficiente para escuchar comodamente en una habitacion.\n\n"
                f"La salida para audifonos de 3.5mm permite escuchar en privado sin molestar a quienes esten cerca, muy util en ambientes compartidos como dormitorios u oficinas.\n\n"
                f"Su diseno compacto y liviano permite llevarlo a cualquier parte: la cocina, el bano, la terraza, un viaje en auto o una caminata en el campo.\n\n"
                f"Un equipo confiable para mantenerse informado, escuchar musica en vivo o simplemente disfrutar la radio tradicional con la calidad de reception que solo da una antena real.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback electronica
        return (
            f"Dispositivo electronico {B}fabricado con componentes de alta calidad que garantizan un rendimiento confiable y duradero en el uso diario.\n\n"
            f"Su diseno compacto y moderno se integra naturalmente en cualquier espacio del hogar u oficina sin generar desorden visual ni ocupar espacio innecesario.\n\n"
            f"Los controles intuitivos permiten que cualquier miembro de la familia lo use sin necesidad de leer el manual, lo cual es especialmente valorado en dispositivos de uso comun.\n\n"
            f"La construccion con materiales de primera calidad se refleja en una durabilidad superior: resiste el uso cotidiano intensivo sin perder funcionalidad ni apariencia.\n\n"
            f"Certificaciones de seguridad internacionales aseguran que cumple con todos los estandares de calidad electrica y seguridad exigidos en el mercado chileno.\n\n"
            f"Compatible con la red electrica chilena de 220V sin necesidad de transformadores ni adaptadores especiales, listo para enchufar y usar desde el primer dia.\n\n"
            f"El servicio post-venta de Maxicompra respalda cada compra con asesoria tecnica disponible para resolver cualquier duda o inconveniente que pueda surgir.\n\n"
            f"Una inversion inteligente para el hogar moderno, donde la tecnologia de calidad hace la vida mas comoda, eficiente y entretenida cada dia.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── COMPUTACION ──────────────────────────────────────────────────────────
    if cat == 'Computacion' or cat == 'Computación':

        if re.search(r'micro.?sd|memoria.*sd|memory card', n):
            gb  = f"de {s['storage']} " if s.get('storage') else ""
            cls = f"Clase {s['clase']} " if s.get('clase') else ""
            return (
                f"La tarjeta de memoria {B}{gb}{cls}es el complemento esencial para ampliar el almacenamiento de smartphones, camaras digitales, camaras de accion, drones y tablets.\n\n"
                f"La alta velocidad de escritura garantiza que las rafagas de fotos en modo continuo se guarden sin perdidas ni demoras, y que los videos en 4K fluyan sin interrupciones.\n\n"
                f"La velocidad de lectura elevada agiliza la transferencia de archivos al computador y permite reproducir contenido multimedia directamente desde la tarjeta sin buffering.\n\n"
                f"El formato microSD ultra compacto encaja en cualquier dispositivo compatible y viene con adaptador SD incluido para usarla tambien en camaras y lectores de tarjetas full-size.\n\n"
                f"La construccion resistente al agua, la temperatura extrema, los rayos X de aeropuerto y los campos magneticos la protege de los riesgos tipicos del uso movil intensivo.\n\n"
                f"La capacidad generosa permite guardar miles de fotos en alta resolucion, horas de video en 4K, musica offline y aplicaciones sin preocuparte por el espacio disponible.\n\n"
                f"Compatible con todos los dispositivos que acepten microSD: smartphones Android, GoPro, drones DJI, Raspberry Pi, Nintendo Switch y mucho mas.\n\n"
                f"Ideal para complementar la memoria interna de tu dispositivo o para tener un almacenamiento removible y portatil que puedas pasar de equipo en equipo.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'\bmouse\b|raton|raton', n):
            ina = re.search(r'inalambrico|wireless', n)
            tipo = "inalambrico" if ina else "con cable"
            return (
                f"El mouse {tipo} {B}eleva la precision y comodidad de uso en cualquier tarea que realices en el computador, desde trabajo de oficina hasta diseno grafico o gaming casual.\n\n"
                f"El sensor optico de alta resolucion DPI ofrece una respuesta precisa y suave en cualquier superficie, eliminando los saltos o imprecisiones que se sienten con mouses de menor calidad.\n\n"
                f"El diseno ergonomico esta esculpido para que la mano descanse naturalmente, reduciendo la tension en la muneca y el antebra​zo durante sesiones largas de trabajo.\n\n"
                f"Los botones principales tienen un click tactico definido y satisfactorio, con durabilidad certificada para millones de pulsaciones sin perder firmeza ni precision.\n\n"
                f"{'El receptor nano USB se guarda dentro del mouse cuando no se usa, protegiendolo de perdidas y danos. La conexion es instantanea y sin interferencias hasta varios metros de distancia.' if ina else 'El cable trenzado de alta resistencia soporta el movimiento constante sin deshilacharse ni perder contacto electrico a lo largo del tiempo.'}\n\n"
                f"La rueda de desplazamiento con resistencia ajustable permite navegar documentos largos, paginas web y hojas de calculo con fluidez y precision.\n\n"
                f"Los botones laterales programables agilizan las tareas frecuentes: avanzar y retroceder en el navegador, cambiar de aplicacion o ejecutar atajos de teclado con un click.\n\n"
                f"Compatible con Windows, macOS y Linux sin necesidad de instalar drivers adicionales. Plug & play funcional desde el primer segundo de uso.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'teclado|keyboard', n):
            return (
                f"El teclado {B}es el punto de contacto mas frecuente entre el usuario y el computador, y este modelo ha sido disenado para que cada interaccion sea mas comoda y eficiente.\n\n"
                f"Las teclas de perfil bajo con recorrido bien calibrado ofrecen una respuesta tactica precisa que satisface tanto a quienes escriben con tecla silenciosa como a quienes prefieren el click definido.\n\n"
                f"El layout incluye todos los caracteres especiales del espanol latinoamericano, facilitando la escritura en Chile sin recurrir a combinaciones de teclas incomodas.\n\n"
                f"La estructura rigida del chasis evita la flexion al escribir con fuerza, manteniendo una base estable que se refleja en mayor precision y menor fatiga en sesiones largas.\n\n"
                f"Las patas regulables en altura permiten ajustar el angulo de inclinacion para encontrar la posicion ergonomica optima y reducir la tension en las munecas.\n\n"
                f"La resistencia a los derrames protege los mecanismos internos de accidentes cotidianos como un vaso de agua o cafe, una situacion que destruye los teclados normales.\n\n"
                f"Compatible con Windows, macOS y la mayoria de sistemas Linux via conexion USB o Bluetooth segun el modelo, plug & play sin instalacion de software adicional.\n\n"
                f"Ideal para oficina en casa, trabajo de texto intensivo, estudiantes universitarios o como upgrade del teclado que viene con el computador de escritorio.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'pendrive|flash drive', n):
            gb = f"de {s['storage']} " if s.get('storage') else ""
            return (
                f"El pendrive {B}{gb}es la forma mas practica y confiable de llevar tus archivos importantes siempre contigo, sin depender de conexion a internet ni de la nube.\n\n"
                f"La velocidad de transferencia USB 3.0 permite copiar una pelicula en alta definicion, miles de fotos o documentos pesados en cuestion de segundos en vez de minutos.\n\n"
                f"La carcasa metalica o de plastico de alta resistencia protege los chips de almacenamiento interno de golpes, presion y campos electromagneticos del uso diario.\n\n"
                f"La tapa protectora del conector evita la acumulacion de polvo, pelusa y humedad que con el tiempo afectan la conectividad de los pendrives sin proteccion.\n\n"
                f"El formato compacto permite tenerlo siempre en el llavero, la billetera o el bolsillo de la mochila, disponible en el momento exacto en que lo necesitas.\n\n"
                f"Compatible con todos los sistemas operativos: Windows, macOS, Linux y ChromeOS, ademas de Smart TVs y consolas de videojuegos con puerto USB.\n\n"
                f"La memoria flash de alta calidad garantiza miles de ciclos de escritura/borrado sin perdida de datos, con una vida util de decadas en condiciones normales de uso.\n\n"
                f"Ideal para presentaciones, backup de documentos importantes, compartir archivos entre dispositivos o llevar tus programas portatiles siempre disponibles.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback computacion
        return (
            f"Accesorio de computacion {B}disenado para optimizar tu experiencia de trabajo y elevar la productividad en cada sesion frente al computador.\n\n"
            f"La compatibilidad universal con los principales sistemas operativos garantiza que funcionara sin problemas desde el primer dia, sin instalaciones complicadas.\n\n"
            f"Los materiales de construccion han sido seleccionados para resistir el uso intensivo diario, con durabilidad verificada en pruebas de ciclos de uso prolongado.\n\n"
            f"El diseno ergonomico considera la postura natural del usuario para reducir la fatiga acumulada en jornadas largas de trabajo o estudio frente al computador.\n\n"
            f"La facilidad de instalacion plug & play elimina la necesidad de conocimientos tecnicos avanzados para comenzar a usarlo inmediatamente.\n\n"
            f"Una inversion que se amortiza rapidamente en terminos de eficiencia ganada, comodidad mejorada y menor desgaste fisico durante las jornadas de trabajo.\n\n"
            f"El respaldo de marca garantiza disponibilidad de soporte tecnico y repuestos en caso de ser necesario durante el periodo de garantia y mas alla.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── TECNOLOGIA ───────────────────────────────────────────────────────────
    if cat == 'Tecnologia' or cat == 'Tecnología':

        if re.search(r'smartwatch|reloj int|smart watch|smart band|pulsera inteligente', n):
            return (
                f"El smartwatch {B}es mucho mas que un reloj: es un centro de monitoreo personal que te mantiene conectado, activo y saludable durante toda la jornada.\n\n"
                f"El monitoreo continuo de la frecuencia cardiaca detecta variaciones en tiempo real, alertandote cuando el ritmo supera los rangos normales durante el ejercicio o el descanso.\n\n"
                f"El seguimiento del sueno analiza tus ciclos de sueno profundo, ligero y REM para entregarte informacion practica sobre como mejorar la calidad de tu descanso nocturno.\n\n"
                f"Los modos de ejercicio multiples detectan automaticamente actividades como caminar, correr, ciclismo, natacion y entrenamiento de fuerza, registrando metricas especificas de cada uno.\n\n"
                f"Las notificaciones del smartphone aparecen discretamente en la pantalla: llamadas, mensajes, correos y alertas de apps, permitiendote decidir cuales merecen tu atencion inmediata.\n\n"
                f"La pantalla AMOLED de alta resolucion es perfectamente legible bajo la luz solar directa, con brillo automatico que se adapta al ambiente sin necesidad de ajustes manuales.\n\n"
                f"La bateria de larga duracion aguanta varios dias de uso continuo sin carga, eliminando la molestia de tener que cargarlo cada noche como un smartphone.\n\n"
                f"Compatible con iOS y Android, la app companion disponible gratis muestra el historico de datos, tendencias y comparaciones para un seguimiento completo de tu salud.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'tablet|ipad', n):
            gb = f"de {s['storage']} " if s.get('storage') else ""
            return (
                f"La tablet {B}{gb}es el dispositivo ideal para quienes buscan la versatilidad de un computador portatil en un formato mas liviano, intuitivo y facil de llevar.\n\n"
                f"La pantalla de alta resolucion con tecnologia IPS ofrece angulos de vision amplios y colores precisos, perfecta para leer, ver series, videoconferencias o editar fotos.\n\n"
                f"El procesador de ultima generacion maneja con fluidez la multitarea: navegar, ver videos en streaming, usar aplicaciones de productividad y jugar sin que nada se trabe.\n\n"
                f"La bateria de gran capacidad aguanta todo el dia de uso continuo con una sola carga, lo que la hace ideal para viajes, clases universitarias o jornadas de trabajo moviles.\n\n"
                f"El acceso a millones de aplicaciones en la tienda oficial abre un universo de posibilidades: desde apps de trabajo y educacion hasta entretenimiento y creatividad.\n\n"
                f"El microfono de alta sensibilidad y los altavoces estereo integrados hacen que las videollamadas con familia y colegas se escuchen con la claridad de estar en persona.\n\n"
                f"La conectividad WiFi de doble banda garantiza velocidades de descarga estables para streaming en 4K, videollamadas sin cortes y sincronizacion rapida de archivos.\n\n"
                f"Ideal para estudiantes, profesionales moviles, adultos mayores que buscan facilidad de uso o cualquier persona que quiera un dispositivo versatil y portatil.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'camara ip|camara ip|cctv|seguridad|vigilancia', n):
            return (
                f"La camara de seguridad {B}te da la tranquilidad de monitorear tu hogar, negocio u oficina en tiempo real desde cualquier lugar del mundo usando solo tu smartphone.\n\n"
                f"La vision nocturna por infrarrojos captura imagenes claras en total oscuridad, garantizando vigilancia efectiva las 24 horas sin importar las condiciones de iluminacion.\n\n"
                f"La deteccion de movimiento inteligente envia alertas instantaneas al telefono cuando detecta actividad inusual, permitiendo una respuesta rapida ante cualquier incidente.\n\n"
                f"La calidad de imagen Full HD o superior captura detalles nitidos como rostros, placas vehiculares o numeracion de prendas, fundamentales en caso de incidente.\n\n"
                f"La conexion WiFi elimina la necesidad de cables de red, simplificando enormemente la instalacion y permitiendo ubicarla en el lugar optimo sin restricciones.\n\n"
                f"El almacenamiento en tarjeta SD local y/o nube garantiza que las grabaciones se conserven incluso si la camara es manipulada o robada por un intruso.\n\n"
                f"La app dedicada disponible para iOS y Android permite ver la imagen en vivo, revisar grabaciones anteriores, ajustar la sensibilidad de deteccion y recibir notificaciones.\n\n"
                f"Instalacion sencilla en menos de 10 minutos sin necesidad de tecnico ni herramientas especiales, con soporte de montaje incluido para pared o techo.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'kit.*limpi|limpiador|limpieza.*pant|spray.*lcd|limpia.*pantalla', n):
            return (
                f"El kit de limpieza {B}es el accesorio indispensable para mantener todas tus pantallas en perfecto estado: desde el televisor y monitor hasta el smartphone, tablet y notebook.\n\n"
                f"La solucion limpiadora de formula especial disuelve las huellas digitales, manchas de grasa y polvo adherido sin atacar los revestimientos antireflex y oleofugos de las pantallas modernas.\n\n"
                f"A diferencia de los limpiadores de uso general, esta formula no contiene alcohol, amoniaco ni acetona, compuestos que deterioran irreversiblemente los paneles OLED, AMOLED y IPS.\n\n"
                f"El pano de microfibra incluido tiene una densidad de fibras que atrapa y retira las particulas de polvo sin rayar la superficie, aunque se aplique presion moderada.\n\n"
                f"La botella con dosificador de spray evita aplicar demasiado liquido de una vez, previniendo que la humedad penetre por los bordes del panel y dane los circuitos internos.\n\n"
                f"Funciona en todos los tipos de pantalla: LCD, LED, OLED, QLED, AMOLED, pantallas tactiles, lentes de gafas, espejos y superficies de vidrio en general.\n\n"
                f"El tamano de viaje de 100ml cumple con las restricciones de liquidos en avion, permitiendo llevarlo en el equipaje de mano para mantener tus dispositivos impecables en viaje.\n\n"
                f"Un kit completo que prolonga la vida util de tus pantallas y mantiene la experiencia visual en su maxima calidad sin recurrir a panos improvisados que pueden rayar.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback tecnologia
        return (
            f"Dispositivo tecnologico {B}que incorpora las funciones mas demandadas por los usuarios modernos en un diseno elegante y de facil operacion.\n\n"
            f"La interfaz intuitiva permite dominar todas sus funciones rapidamente, sin curvas de aprendizaje largas ni manuales tecnicos complejos de entender.\n\n"
            f"La conectividad actualizada asegura compatibilidad con los dispositivos y redes actuales, preparando el equipo para seguir siendo relevante en los proximos anos.\n\n"
            f"Los materiales de construccion premium se notan al tacto: solidez, peso equilibrado y acabados que transmiten calidad y justifican la inversion a largo plazo.\n\n"
            f"El consumo energetico optimizado reduce el impacto en la cuenta de luz y en el medioambiente, alineado con las tendencias globales de eficiencia energetica.\n\n"
            f"El ecosistema de apps y accesorios compatibles amplia enormemente las posibilidades de uso, convirtiendo este equipo en el centro de multiples actividades cotidianas.\n\n"
            f"El soporte tecnico disponible en Chile y la garantia valida localmente ofrecen la tranquilidad de que cualquier inconveniente tiene solucion rapida y accesible.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── HOGAR ────────────────────────────────────────────────────────────────
    if cat == 'Hogar':

        if re.search(r'aspiradora|aspirador|vacuum', n):
            return (
                f"La aspiradora {B}transforma la tarea de limpiar pisos en una actividad rapida, eficiente y libre del esfuerzo fisico asociado a la limpieza manual con escoba.\n\n"
                f"El motor de alto rendimiento genera una succion potente que levanta polvo fino, pelos de mascota, migas, arena y residuos de todo tipo en una sola pasada.\n\n"
                f"El filtro HEPA captura particulas de hasta 0.3 micrones, incluyendo alergenos, acaro del polvo y esporas de hongo, mejorando significativamente la calidad del aire interior.\n\n"
                f"Los cabezales intercambiables incluidos permiten adaptar la aspiradora a cada superficie: alfombras, pisos duros, tapizados de sofa, escaleras y rincon de dificil acceso.\n\n"
                f"El deposito de polvo de vaciado rapido y limpieza sencilla elimina el contacto directo con la suciedad y la necesidad de comprar bolsas de repuesto continuamente.\n\n"
                f"El largo del cable y de las extensiones del tubo dan libertad de movimiento para cubrir habitaciones grandes sin tener que cambiar de enchufe constantemente.\n\n"
                f"El nivel de ruido reducido la hace mas agradable para los demas miembros del hogar, incluyendo mascotas que suelen asustarse con el sonido de las aspiradoras tradicionales.\n\n"
                f"Un electrodomestico que una vez que lo pruebas no entiendes como vivias sin el: la limpieza del hogar pasa de ser una tarea pesada a un proceso rapido y efectivo.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'plancha|iron\b', n):
            return (
                f"La plancha {B}lleva el proceso de planchado a otro nivel gracias a su combinacion de suela deslizante de primera calidad y sistema de vapor de alta presion.\n\n"
                f"La suela ceramica o de acero inoxidable pulido desliza con suavidad sobre todo tipo de telas, desde el lino mas resistente hasta las telas mas delicadas como la seda.\n\n"
                f"El sistema de vapor de alta presion penetra en las fibras del tejido desde adentro para eliminar las arrugas mas persistentes en una sola pasada, sin tener que repetir.\n\n"
                f"El termostato de precision ajusta la temperatura exacta recomendada para cada tipo de tela, evitando el riesgo de quemar o brilla inadvertidamente prendas delicadas.\n\n"
                f"El calentamiento rapido alcanza la temperatura optima de trabajo en menos de 30 segundos, reduciendo el tiempo de espera antes de comenzar a planchar.\n\n"
                f"La funcion de vapor extra permite un chorro puntual de vapor de alta potencia para atacar las arrugas mas difíciles en cuellos, mangas y costuras sin esfuerzo adicional.\n\n"
                f"El deposito de agua de buena capacidad evita interrupciones frecuentes para rellenarlo, permitiendo planchar una tanda completa de ropa sin pausas molestas.\n\n"
                f"El apagado automatico de seguridad protege la plancha y la ropa si se olvida horizontalmente o de pie por mas tiempo del necesario, previniendo accidentes.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'ventilador|fan\b', n):
            return (
                f"El ventilador {B}ofrece la solucion mas eficiente y economica para mantener el confort termico en el hogar durante los meses calurosos del verano chileno.\n\n"
                f"El motor de corriente continua de ultima generacion consume significativamente menos energia que los ventiladores tradicionales, generando un ahorro real en la cuenta de luz.\n\n"
                f"Las multiples velocidades de viento permiten ajustar el flujo de aire exacto para cada situacion: desde una brisa suave para dormir hasta el maximo para dias de calor extremo.\n\n"
                f"El movimiento oscilante distribuye el aire fresco de manera uniforme por toda la habitacion, eliminando los puntos calientes y garantizando comodidad para todos.\n\n"
                f"El modo de funcionamiento silencioso es especialmente valorado en dormitorios: genera el viento necesario para dormir fresco sin el ruido que interrumpe el descanso.\n\n"
                f"El control remoto incluido permite ajustar la velocidad, el timer y el modo de oscilacion desde la cama o el sofa sin tener que levantarse cada vez.\n\n"
                f"La estructura de montaje estable en pie o sobre mesa le da flexibilidad de ubicacion en cualquier espacio, con un diseno que no hace ruido ni vibra al funcionar.\n\n"
                f"El timer programable apaga el ventilador automaticamente tras el tiempo que configures, perfecto para dormir frescos sin que funcione innecesariamente toda la noche.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback hogar
        return (
            f"Articulo para el hogar {B}que combina funcionalidad practica con un diseno cuidado, pensado para integrarse armoniosamente en cualquier espacio domestico moderno.\n\n"
            f"Los materiales de construccion han sido seleccionados para resistir el uso cotidiano intensivo que se da en un hogar activo, manteniendo su apariencia y funcionalidad con el tiempo.\n\n"
            f"El diseno intuitivo hace que cualquier miembro de la familia pueda usarlo correctamente desde el primer momento, sin instrucciones ni configuraciones complejas.\n\n"
            f"Su mantenimiento es simple: los componentes estan pensados para limpiarse y cuidarse facilmente, prolongando la vida util del producto sin esfuerzo extra.\n\n"
            f"El tamano y peso han sido optimizados para que no ocupe mas espacio del necesario, adaptandose a cocinas, dormitorios, banos y espacios de living de cualquier tamano.\n\n"
            f"La relacion calidad-precio lo posiciona como una opcion inteligente frente a alternativas mas costosas que no ofrecen un rendimiento notablemente superior en el uso diario.\n\n"
            f"Cada compra en Maxicompra incluye el respaldo de garantia y la posibilidad de contacto directo con el equipo de post-venta para cualquier consulta o inconveniente.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── JUGUETES ─────────────────────────────────────────────────────────────
    if cat == 'Juguetes':

        if re.search(r'control remoto|\brc\b|teledirigido', n):
            return (
                f"El juguete de control remoto {B}combina la emocion de la velocidad con el desarrollo de habilidades psicomotrices en una experiencia que engancha a ninos y adultos por igual.\n\n"
                f"El control ergonomico con agarre comodo permite maniobras precisas incluso en espacios reducidos, desarrollando la coordinacion ojo-mano de manera natural y divertida.\n\n"
                f"Las velocidades multiples se adaptan a la experiencia del conductor: velocidad reducida para comenzar y potencia maxima para quienes ya dominan el manejo.\n\n"
                f"La bateria recargable del vehiculo se carga rapido y proporciona buena autonomia de juego, suficiente para sesiones largas sin interrupciones frustrantes.\n\n"
                f"El diseno robusto soporta los choques, caidas y topetones tipicos del uso infantil intensivo, con piezas que no se rompen ante el primer golpe contra una pared.\n\n"
                f"La frecuencia de control permite que dos unidades del mismo modelo se usen simultaneamente sin interferencias, ideal para carreras entre hermanos o amigos.\n\n"
                f"El tamano y peso son apropiados para que ninos desde los 6 anos puedan manejarlo solos con seguridad, mientras que la velocidad genera suficiente emocion para el segmento mayor.\n\n"
                f"Incluye todos los accesorios necesarios para empezar a jugar inmediatamente al abrir la caja: control, vehiculo, cargador y pilas segun el modelo.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'educativo|didactico|didáctico|puzzle|rompecabezas', n):
            return (
                f"El juguete educativo {B}demuestra que aprender y divertirse no son actividades excluyentes sino que se potencian mutuamente cuando el diseno del juguete es el correcto.\n\n"
                f"Cada elemento del diseno ha sido pensado para estimular areas especificas del desarrollo infantil: atencion, memoria, razonamiento logico y coordinacion fina.\n\n"
                f"Las piezas de tamano apropiado para la edad objetivo son seguras, sin bordes cortantes ni piezas pequenas que representen riesgo de ingestion para los mas chicos.\n\n"
                f"Los colores vibrantes y los materiales tactilmente interesantes mantienen la atencion del nino por periodos mas largos, maximizando el tiempo de aprendizaje activo.\n\n"
                f"La progresion de dificultad mantiene al nino siempre en su zona de desarrollo proximo: ni tan facil que se aburra ni tan dificil que se frustre y abandone.\n\n"
                f"La durabilidad de los materiales permite que el juguete sobreviva anos de uso intensivo y pueda ser heredado por hermanos menores o compartido en ambientes educativos.\n\n"
                f"Los materiales no toxicos certificados garantizan seguridad total incluso si el nino lo lleva a la boca, cumpliendo con los estandares internacionales de seguridad infantil.\n\n"
                f"Un regalo que los padres pueden dar con la confianza de que aporta valor real al desarrollo de sus hijos, no solo entretenimiento pasajero.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback juguetes
        return (
            f"El juguete {B}esta disenado para capturar la atencion y la imaginacion de los ninos con una propuesta de juego que combina emocion y aprendizaje en cada sesion.\n\n"
            f"Los materiales de fabricacion han pasado por rigurosas pruebas de seguridad infantil, certificando que son no toxicos, libres de BPA y seguros para el uso con supervision.\n\n"
            f"El diseno visual atractivo con colores vibrantes genera atraccion inmediata, mientras que la mecanica de juego mantiene el interes sostenido mas alla del primer impacto.\n\n"
            f"La construccion robusta soporta el uso intensivo tipico del juego infantil: caidas, golpes, manipulacion brusca y las inevitables travesuras que acompanan la infancia.\n\n"
            f"El rango de edad recomendado ha sido determinado por especialistas en desarrollo infantil para garantizar que el desafio y la seguridad esten apropiadamente equilibrados.\n\n"
            f"La facilidad de uso permite que el nino juegue de manera autonoma, desarrollando su independencia y la confianza en sus propias habilidades para resolver desafios.\n\n"
            f"Perfecto como regalo de cumpleanos, navidad o sin ocasion especial para cualquier nino que merece un juguete que realmente lo haga sonreir.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── SALUD & BELLEZA ──────────────────────────────────────────────────────
    if cat == 'Salud & Belleza' or cat == 'Salud &amp; Belleza':

        if re.search(r'afeitadora|afeitador|rasuradora|shaver', n):
            humsec = 'humedo' in n and 'seco' in n
            tipo   = "de uso en seco y humedo" if humsec else "electrica"
            return (
                f"La afeitadora {tipo} {B}redefine la rutina de afeitado diaria gracias a su tecnologia de corte preciso que logra resultados limpios sin la irritacion del afeitado manual.\n\n"
                f"El cabezal flotante con multiples laminas se adapta a los contornos del rostro en tiempo real, llegando a las zonas mas dificiles como el cuello y la mandibula sin esfuerzo.\n\n"
                f"{'El uso en humedo permite afeitar con gel o espuma de afeitar para mayor suavidad, mientras que el modo seco es perfecto para las mananas con prisa.' if humsec else 'La potencia del motor garantiza una pasada limpia incluso en barbas de varios dias sin tirones ni irritacion.'}\n\n"
                f"El sistema de corte de triple o doble accion captura los pelos en distintos angulos y longitudes en una sola pasada, reduciendo el numero de movimientos necesarios.\n\n"
                f"La bateria de litio de larga duracion proporciona varias semanas de uso diario con una sola carga, y el indicador de bateria avisa con anticipacion cuando es momento de recargar.\n\n"
                f"El cabezal desmontable y lavable bajo el grifo simplifica enormemente la limpieza: enjuaga los restos de pelo en segundos para mantener la higiene del equipo.\n\n"
                f"La ergonomia del mango ha sido estudiada para garantizar un agarre seguro y comodo en cualquier angulo, incluyendo las zonas de dificil acceso del cuello.\n\n"
                f"Un aliado diario que transforma el afeitado de una tarea que se evita a un ritual rapido y agradable que deja la piel suave y presentable sin esfuerzo.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'balanza|bascula|pesa digital|peso digital', n):
            kg = f"con capacidad de hasta {s['kg']} kg " if s.get('kg') else ""
            return (
                f"La balanza digital {B}{kg}es el instrumento de medicion esencial para el control preciso del peso en el hogar, la cocina gourmet, el fitness o el comercio minorista.\n\n"
                f"La celda de carga de precision garantiza lecturas exactas hasta el gramo, fundamentales para recetas de reposteria, control de porciones nutricionales o pesaje comercial.\n\n"
                f"La pantalla LCD de alta visibilidad muestra los resultados claramente incluso bajo iluminacion directa o en angulos oblicuos, sin necesidad de posicionarla perfectamente.\n\n"
                f"La funcion tara permite restar el peso del recipiente o envase, midiendo solo el contenido neto con un simple toque de boton, agilizando cualquier proceso de pesaje.\n\n"
                f"La plataforma de acero inoxidable resistente a la corrosion soporta el uso continuo y es facil de limpiar con un pano humedo, manteniendo la higiene en ambientes de cocina.\n\n"
                f"El apagado automatico conserva la bateria cuando no se usa, con una vida util de bateria que permite cientos de sesiones de pesaje antes de necesitar cambio.\n\n"
                f"Las unidades de medicion multiples (gramos, kilogramos, libras, onzas) permiten adaptarla a diferentes contextos sin conversiones manuales que generan errores.\n\n"
                f"Compacta y de poco peso, cabe en cualquier cajon de cocina o se puede exhibir en el mesón sin que tome espacio innecesario.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback salud
        return (
            f"Producto de salud y cuidado personal {B}que incorpora tecnologia avanzada para ofrecerte resultados de nivel profesional en la comodidad de tu hogar.\n\n"
            f"El diseno ergonomico facilita el uso autonomo sin necesidad de asistencia, con controles intuitivos que cualquier persona puede dominar desde el primer uso.\n\n"
            f"Los materiales en contacto con la piel han sido seleccionados por su hipoalergenicidad y suavidad, minimizando el riesgo de irritacion incluso en pieles sensibles.\n\n"
            f"La eficiencia energetica del motor o sistema interno garantiza resultados optimos con el minimo consumo, prolongando la vida de la bateria y reduciendo costos operativos.\n\n"
            f"Los accesorios incluidos multiplican las posibilidades de uso, adaptando el producto a diferentes necesidades y zonas del cuerpo o face de la rutina de cuidado personal.\n\n"
            f"La facilidad de limpieza y mantenimiento garantiza higiene optima en cada uso, con componentes desmontables que se enjuagan en segundos bajo el agua.\n\n"
            f"Una inversion en bienestar personal que se amortiza rapidamente al reemplazar visitas a salones o centros de estetica por resultados equivalentes desde casa.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── TELEFONIA ────────────────────────────────────────────────────────────
    if cat == 'Telefonia' or cat == 'Telefonía':

        if re.search(r'galaxy|iphone|smartphone|celular|xiaomi|motorola|redmi|a\d{2}|note\s?\d', n):
            gb = f"de {s['storage']} " if s.get('storage') else ""
            return (
                f"El smartphone {B}{gb}ofrece el equilibrio ideal entre rendimiento, camara de calidad y bateria de larga duracion que la mayoria de los usuarios necesita en su dia a dia.\n\n"
                f"El procesador de ultima generacion maneja con fluidez las aplicaciones de mensajeria, redes sociales, streaming de video y multitarea sin tirones ni cierres inesperados.\n\n"
                f"El sistema de camaras multiples captura fotos con nivel de detalle, rango dinamico y rendimiento en poca luz que antes solo encontrabas en equipos de alta gama.\n\n"
                f"La bateria de gran capacidad aguanta un dia completo de uso normal incluyendo llamadas, mensajeria, redes sociales, musica y navegacion sin necesidad de recarga intermedia.\n\n"
                f"La pantalla de alta resolucion con tecnologia AMOLED o IPS ofrece colores vibrantes y negros profundos para disfrutar de contenido multimedia con calidad de display premium.\n\n"
                f"El almacenamiento interno ampliado {gb}permite guardar las apps favoritas, la musica offline, las fotos de los ultimos anos y los documentos de trabajo sin quedarse sin espacio.\n\n"
                f"La conectividad 4G LTE asegura velocidades de navegacion rapidas en cualquier punto del pais con cobertura de red, fundamentales para videollamadas y streaming sin cortes.\n\n"
                f"Incluye cargador en caja y funciona con las tarjetas SIM de todos los operadores chilenos. Compatible con actualizaciones de sistema operativo por varios anos.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'funda|case|carcasa|protector.*celular', n):
            return (
                f"La funda protectora {B}es el accesorio mas importante que puedes agregar a tu smartphone: una capa de proteccion que puede salvarte de un gasto importante ante una caida.\n\n"
                f"El material de absorcion de impactos amortigua la energia de las caidas antes de que llegue al cuerpo del telefono, protegiendo la pantalla, las camaras y la carcasa.\n\n"
                f"El diseno ajustado al modelo especifico garantiza que todos los puertos, botones y la camara queden perfectamente accesibles sin que la funda interfiera con la usabilidad.\n\n"
                f"El acabado texturizado en los laterales mejora significativamente el agarre del telefono, reduciendo la probabilidad de que se resbale de las manos en el uso cotidiano.\n\n"
                f"El grosor cuidadosamente calibrado agrega proteccion real sin hacer que el telefono se sienta como un ladrillo en el bolsillo, manteniendo la estetica slim del diseno original.\n\n"
                f"Los bordes levantados alrededor de la pantalla y el modulo de camara crean una zona de proteccion cuando el telefono cae boca abajo, evitando el contacto directo con el suelo.\n\n"
                f"La resistencia al amarillamiento del material garantiza que la funda transparente o de color mantendra su aspecto original por mucho mas tiempo que las fundas baratas.\n\n"
                f"Compatible especificamente con el modelo indicado, asegurando el ajuste perfecto que las fundas universales nunca logran. Un accesorio que se paga a si mismo en la primera caida evitada.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'vidrio templado|glass|protector.*pantalla', n):
            return (
                f"El protector de pantalla {B}de vidrio templado 9H es la primera linea de defensa de la pantalla de tu smartphone contra rayones, impactos y caidas cotidianas.\n\n"
                f"La dureza 9H en la escala Mohs es la misma que tienen las pantallas de alta gama: resiste las llaves, monedas y objetos metalicos que tipicamente rayan las pantallas desprotegidas.\n\n"
                f"La adhesion de silicona de gel permite una instalacion sin burbujas que cualquier persona puede realizar en su casa siguiendo las instrucciones incluidas en menos de 5 minutos.\n\n"
                f"La transmision de luz superior al 99% no altera la calidad de imagen de la pantalla ni reduce el brillo percibido, manteniendola exactamente como la diseno el fabricante.\n\n"
                f"La sensibilidad tactil intacta garantiza que los gestos de deslizamiento rapido, el reconocimiento de huellas bajo pantalla y la escritura respondan sin diferencia perceptible.\n\n"
                f"El recubrimiento oleofugo rechaza las huellas digitales y las manchas de grasa, facilitando la limpieza con un simple pano de microfibra.\n\n"
                f"En caso de impacto, el vidrio templado absorbe la energia del golpe y se quiebra el en lugar de la pantalla original, que es exponencialmente mas cara de reparar.\n\n"
                f"Cortado con precision laser para el modelo especificado, asegurando que cubre toda la pantalla sin dejar bordes sin proteccion ni interferir con la funda.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback telefonia
        return (
            f"Accesorio de telefonia {B}fabricado con materiales de alta calidad para complementar y proteger tu smartphone durante el uso diario.\n\n"
            f"La compatibilidad especifica con los modelos indicados garantiza el ajuste perfecto que un accesorio universal jamas puede ofrecer.\n\n"
            f"El diseno ha sido validado por usuarios reales para asegurar que no interfiere con ninguna funcion del telefono: camara, microfono, parlante, puertos y botones.\n\n"
            f"Los controles de calidad en fabricacion garantizan que cada unidad que llega a tus manos cumple con los estandares minimos de durabilidad y ajuste.\n\n"
            f"La facilidad de instalacion o uso lo hace accesible para cualquier persona sin necesidad de conocimientos tecnicos ni herramientas especiales.\n\n"
            f"Una proteccion o mejora que nuestros clientes suelen describir como uno de esos accesorios que no entiendes por que no compraste antes cuando lo tienes.\n\n"
            f"Producto original disponible en Maxicompra con garantia y respaldo post-venta para cualquier consulta o inconveniente.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── COCINA ───────────────────────────────────────────────────────────────
    if cat == 'Cocina':

        if re.search(r'sarten|sarten|paila|wok', n):
            return (
                f"La sarten {B}con revestimiento antiadherente de alta durabilidad transforma la experiencia de cocinar al eliminar el problema del pegado y simplificar radicalmente la limpieza.\n\n"
                f"La capa antiadherente de alta calidad permite cocinar con minimo o sin aceite, haciendo las preparaciones mas saludables sin sacrificar el sabor ni la textura final.\n\n"
                f"El fondo difusor de alta eficiencia distribuye el calor de manera uniforme en toda la superficie, eliminando los puntos calientes que queman los alimentos en el centro.\n\n"
                f"La compatibilidad con cocinas a gas, electrica, vitroceramica e induccion la hace versatil para cualquier tipo de cocina, sin necesidad de tener utensilios distintos.\n\n"
                f"El mango ergonomico de triple remache garantiza una union solida que no se afloja con el tiempo, con recubrimiento termico que lo mantiene frio durante la coccion.\n\n"
                f"Los bordes levantados facilitan mezclar y saltear los alimentos sin que caigan fuera, y el interior espacioso permite preparar porciones para toda la familia.\n\n"
                f"La limpieza es tan simple como pasar un pano humedo: los restos de comida no se adhieren a la superficie, ahorrando tiempo y esfuerzo en el lavado post-coccion.\n\n"
                f"Un utensilio de cocina que una vez que lo pruebas no quieres volver a los anteriores: la comodidad y versatilidad justifican ampliamente la inversion.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'batidora|mixer|amasadora', n):
            return (
                f"La batidora {B}convierte la preparacion de reposteria, cocteleria y cocina en general en una tarea rapida, limpia y con resultados profesionales desde casa.\n\n"
                f"El motor de alto torque mantiene la velocidad constante incluso con mezclas densas como masas de pan o cremas de mantequilla, sin perder revoluciones bajo carga.\n\n"
                f"Los accesorios intercambiables incluidos multiplican las posibilidades: varillas para batir claras, ganchos amasadores para masas y paleta para mezclas medianas.\n\n"
                f"Las multiples velocidades con graduacion precisa permiten comenzar lentamente para evitar salpicaduras y aumentar progresivamente segun lo requiera la receta.\n\n"
                f"El bol de gran capacidad en acero inoxidable resiste los impactos y temperaturas extremas, y puede lavarse en lavavajillas sin perder brillo ni forma con el tiempo.\n\n"
                f"La estabilidad del mecanismo de sujecion del bol evita que se mueva durante el batido, incluso a maxima potencia, evitando accidentes y derrames.\n\n"
                f"La facilidad de cambio entre accesorios y la limpieza rapida de todas las partes la convierten en el centro de la cocina para quienes disfrutan preparar postres y panes en casa.\n\n"
                f"Compatible con los accesrios de la misma linea de la marca para ampliar las posibilidades culinarias en el futuro sin necesidad de comprar una batidora nueva.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        if re.search(r'aire frito|air fryer|freidora', n):
            return (
                f"La freidora de aire {B}es la revolucion de la cocina saludable: logra el resultado crujiente de la fritura tradicional usando hasta un 80% menos de aceite.\n\n"
                f"La tecnologia de circulacion de aire caliente a alta velocidad envuelve los alimentos de manera uniforme, cocinando el exterior perfectamente dorado y crujiente sin sumergirlos en aceite.\n\n"
                f"La temperatura programable y el timer digital permiten configurar exactamente las condiciones de coccion de cada receta, reproduciendo resultados perfectos cada vez.\n\n"
                f"La canasta antiadherente de gran capacidad cocina porciones familiares de papas fritas, nuggets, alitas, verduras o pescado en una sola tanda sin necesidad de hacer turnos.\n\n"
                f"El tiempo de precalentamiento es minimo comparado con el horno convencional: en minutos el equipo esta a temperatura y listo para comenzar la coccion.\n\n"
                f"Los presets de coccion para los alimentos mas frecuentes eliminan la necesidad de memorizar tiempos y temperaturas: un toque y el equipo hace el resto solo.\n\n"
                f"La limpieza es sorprendentemente sencilla: la canasta y el recipiente son aptos para lavavajillas, y la ausencia de aceite en las paredes internas facilita el mantenimiento.\n\n"
                f"Una vez que integras la freidora de aire a tu rutina, te preguntaras como cocinabas antes: mas rapido, mas sano y con menos olor a fritura en toda la casa.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )

        # fallback cocina
        return (
            f"Electrodomestico de cocina {B}que simplifica las tareas culinarias diarias y eleva los resultados a un nivel que antes requeria mucho mas tiempo y esfuerzo.\n\n"
            f"Los materiales en contacto con alimentos cumplen con las normativas de seguridad alimentaria, garantizando que no se transfieren sustancias nocivas a las preparaciones.\n\n"
            f"El diseno ergonomico y la interfaz intuitiva permiten que cualquier persona, independientemente de su experiencia en la cocina, obtenga buenos resultados desde el primer uso.\n\n"
            f"La potencia calibrada del motor o sistema de calefaccion garantiza eficiencia energetica sin sacrificar los tiempos de coccion ni la calidad del resultado final.\n\n"
            f"La facilidad de limpieza post-coccion es uno de los aspectos mas valorados por los usuarios: los componentes desmontables se limpian rapido y algunos son aptos para lavavajillas.\n\n"
            f"El diseno compacto ocupa el espacio justo en la mesada o en el armario, sin invadir el espacio de trabajo de la cocina que siempre es mas limitado de lo que uno quisiera.\n\n"
            f"Un aporte concreto a la calidad de vida en el hogar: menos tiempo en la cocina, mejores resultados y la satisfaccion de preparar comida rica para la familia.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── ACCESORIOS ───────────────────────────────────────────────────────────
    if cat == 'Accesorios':
        if re.search(r'piscina|inflable|pileta', n):
            return (
                f"La piscina inflable {B}es la forma mas accesible y practica de tener una piscina propia en casa para disfrutar el verano chileno al maximo sin grandes inversiones.\n\n"
                f"El material PVC de alta densidad resiste la exposicion prolongada a los rayos UV del sol sin decolorarse ni perder flexibilidad durante toda la temporada de uso.\n\n"
                f"Las multiples camaras de aire independientes garantizan que si una zona pierde presion, el resto mantiene la estructura, dandote tiempo para reparar sin que la piscina colapse.\n\n"
                f"El sistema de vaciado rapido por la valvula ubicada en la base permite vaciarla y guardarla en minutos cuando termina la temporada o cuando el espacio lo requiere.\n\n"
                f"El fondo plano y la forma estable crean una zona segura para ninos que estan aprendiendo a nadar, con una profundidad apropiada para supervision adulta constante.\n\n"
                f"Las dimensiones generosas acomodan a varios ninos o adultos simultaneamente, haciendo de ella el punto de reunion del verano en patios y jardines.\n\n"
                f"El inflado y desinflado son sencillos con una bomba de aire manual o electrica: en minutos la piscina pasa de estar guardada en su caja a estar lista para el chapoteo.\n\n"
                f"Una opcion economica y versatil para familias que quieren refrescarse en casa sin el costo ni el espacio que requiere una piscina fija permanente.\n\n"
                f"Despacho rapido a todo Chile con garantia incluida."
            )
        return (
            f"Accesorio {B}de calidad premium fabricado con materiales seleccionados para ofrecer durabilidad y rendimiento superiores en su categoria de precio.\n\n"
            f"El diseno especifico para los modelos compatibles garantiza un ajuste y funcionamiento optimo que los accesorios genericos no pueden replicar.\n\n"
            f"Cada detalle de construccion ha sido pensado para la comodidad de uso: materiales tacticos agradables, geometria ergonomica y peso equilibrado.\n\n"
            f"La durabilidad verificada en pruebas de ciclos de uso intensivo asegura que mantendra su rendimiento y apariencia mucho mas alla de lo que sugiere el precio.\n\n"
            f"Compatibilidad amplia con los modelos mas populares del mercado, verificada antes de listar el producto para evitar inconvenientes post-compra.\n\n"
            f"La facilidad de instalacion o uso sin herramientas ni conocimientos tecnicos especiales lo hace accesible para cualquier perfil de usuario.\n\n"
            f"Producto disponible en Maxicompra con garantia y soporte post-venta directo para resolver cualquier consulta o inconveniente que pueda surgir.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── DEPORTES ─────────────────────────────────────────────────────────────
    if cat == 'Deportes':
        return (
            f"Articulo deportivo {B}disenado en colaboracion con atletas y entrenadores para satisfacer las demandas reales del rendimiento en entrenamiento y competencia.\n\n"
            f"Los materiales tecnicos utilizados en su fabricacion son los mismos que se encuentran en equipamiento de uso profesional, disponibles ahora a un precio accesible.\n\n"
            f"La ergonomia especifica para la actividad que este articulo acompana maximiza la eficiencia del movimiento y reduce el riesgo de lesiones por uso inadecuado del equipo.\n\n"
            f"La durabilidad es uno de sus atributos mas destacados: soporta sesiones de entrenamiento intenso repetidas sin perder forma, funcionalidad ni propiedades tecnicas.\n\n"
            f"La versatilidad de uso lo hace valioso tanto para principiantes que estan comenzando su actividad fisica como para deportistas avanzados con rutinas exigentes.\n\n"
            f"El mantenimiento es simple y rapido, permitiendo dedicar el tiempo al entrenamiento en lugar de al cuidado del equipamiento despues de cada sesion.\n\n"
            f"Una inversion en salud y rendimiento fisico que se amortiza en cada sesion de ejercicio, siendo el complemento perfecto para alcanzar tus objetivos deportivos.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    # ── GENERAL / FALLBACK ───────────────────────────────────────────────────
    if re.search(r'zapatilla|regleta|alargador|enchufe multiple', n):
        tomas = f"de {s['pack']} tomas " if s.get('pack') else ""
        return (
            f"La zapatilla electrica {B}{tomas}es el accesorio indispensable para cualquier espacio donde la demanda de enchufes supera la oferta disponible en la pared.\n\n"
            f"El protector contra sobretensiones integrado actua como escudo para todos los equipos conectados, desconectandolos si el voltaje supera niveles seguros.\n\n"
            f"Cada toma acepta clavijas chilenas de dos y tres pines con contacto firme, evitando microcortes que danan equipos electronicos sensibles.\n\n"
            f"El cable de longitud generosa permite ubicar la zapatilla donde mas se necesita sin estar limitado por la posicion del enchufe de pared.\n\n"
            f"El interruptor maestro con indicador luminoso apaga todos los equipos con un solo movimiento, eliminando el consumo fantasma durante la noche.\n\n"
            f"La carcasa ignifuga resiste temperaturas elevadas sin deformarse ni generar riesgos, cumpliendo los estandares de seguridad electrica vigentes en Chile.\n\n"
            f"Ideal para escritorio, home theater, setup gamer, cocina o cualquier zona donde se concentran multiples equipos electronicos simultaneamente.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    if re.search(r'piscina|inflable|pileta', n):
        return (
            f"La piscina inflable {B}es la forma mas accesible de tener una piscina propia en casa para disfrutar el verano sin grandes inversiones ni obras.\n\n"
            f"El PVC de alta densidad resiste los rayos UV del sol durante toda la temporada sin decolorarse ni perder la resistencia que le da la estructura.\n\n"
            f"Las multiples camaras de aire independientes garantizan seguridad: si una zona pierde presion, el resto mantiene la estructura sin colapso inmediato.\n\n"
            f"El sistema de vaciado rapido permite dejarla sin agua y guardarla en su bolsa en pocos minutos cuando el espacio lo requiere.\n\n"
            f"Las dimensiones generosas acomodan a toda la familia, convirtiendo el patio o jardin en el punto de encuentro del verano.\n\n"
            f"El inflado y desinflado son sencillos con cualquier bomba de aire: en minutos pasa de estar guardada a lista para el chapoteo.\n\n"
            f"Una opcion perfecta para familias que quieren refrescarse en casa sin el costo ni el espacio que requiere una piscina fija permanente.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    if re.search(r'kit.*limpi|limpiador|limpieza.*pant|spray.*lcd', n):
        return (
            f"El kit de limpieza {B}es el accesorio indispensable para mantener todas tus pantallas impecables: desde el televisor hasta el smartphone, tablet y notebook.\n\n"
            f"La formula especial sin alcohol ni amoniaco disuelve huellas digitales y grasa sin atacar los revestimientos antireflex ni las capas oleofugas de las pantallas modernas.\n\n"
            f"El pano de microfibra de alta densidad atrapa particulas de polvo sin rayar la superficie, incluso con presion moderada en manchas difíciles.\n\n"
            f"La botella con dosificador evita aplicar demasiado liquido, previniendo que la humedad penetre por los bordes del panel y dane los circuitos.\n\n"
            f"Compatible con todos los tipos de pantalla: LCD, LED, OLED, QLED, AMOLED, pantallas tactiles y lentes de gafas.\n\n"
            f"El tamano de 100ml cumple las restricciones de liquidos en avion para llevarlo en el equipaje de mano y mantener tus equipos impecables en viaje.\n\n"
            f"Prolonga la vida util de tus pantallas y mantiene la experiencia visual en su maximo potencial sin riesgo de rayaduras ni danos quimicos.\n\n"
            f"Despacho rapido a todo Chile con garantia incluida."
        )

    return (
        f"Producto {B}de calidad garantizada para el uso diario, fabricado con materiales seleccionados que equilibran rendimiento y durabilidad a un precio justo.\n\n"
        f"El diseno practico e intuitivo fue disenado para que cualquier persona pueda sacarle el maximo provecho desde el primer momento, sin instrucciones complejas.\n\n"
        f"La construccion solida resiste el uso cotidiano intensivo tipico de un hogar activo, manteniendo su funcionalidad y apariencia a lo largo del tiempo.\n\n"
        f"La compatibilidad con los estandares chilenos de voltaje, enchufe y normativas de seguridad garantiza un funcionamiento optimo sin necesidad de adaptadores.\n\n"
        f"Cada unidad pasa por un control de calidad antes de ser despachada, asegurando que lo que recibes cumple con las especificaciones del fabricante.\n\n"
        f"El soporte post-venta de Maxicompra esta disponible para resolver cualquier duda o inconveniente que pueda surgir durante el uso del producto.\n\n"
        f"Una compra respaldada por la confianza de miles de clientes satisfechos en todo Chile que eligen Maxicompra por la calidad y la rapidez del servicio.\n\n"
        f"Despacho rapido a todo Chile con garantia incluida."
    )


# ── Main ────────────────────────────────────────────────────────────────────

with open('products_backup.json', encoding='utf-8') as f:
    data = json.load(f)

prods = data.get('products', [])
desc_map = {}

for p in prods:
    old = p.get('desc', '') or ''
    needs = (
        len(old.strip()) < 400
        or 'Vendido por Maxicompra' in old
        or old.strip() == (p.get('name','') or '').strip()
    )
    if needs:
        new_desc = generate_desc(p)
        p['desc'] = new_desc
        desc_map[p['id']] = new_desc

print(f"Actualizados: {len(desc_map)} de {len(prods)} productos")

# Muestra 3 ejemplos
from collections import defaultdict
samples = defaultdict(list)
for p in prods:
    if p['id'] in desc_map:
        samples[p.get('cat','?')].append(p)

shown = 0
for cat, ps in sorted(samples.items()):
    if shown >= 3: break
    p = ps[0]
    print(f"\n{'='*60}")
    print(f"[{cat}] {p['name'][:70]}")
    print(f"{'='*60}")
    print(p['desc'])
    shown += 1

with open('products_updated.json', 'w', encoding='utf-8') as f:
    json.dump({'products': prods}, f, ensure_ascii=False, indent=2)

print(f"\nGuardado: products_updated.json")
