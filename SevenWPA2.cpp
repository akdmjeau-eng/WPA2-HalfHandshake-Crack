// Lógica para añadir dentro del bloque: if ((type_subtype & 0xFC) == 0x40)

// Posición de inicio de los Information Elements (justo después del encabezado de gestión)
// El encabezado fijo de un Probe Request no siempre incluye campos adicionales antes de los IEs.
const u_char* ie_start = dot11_base + sizeof(Dot11MgtHeader);
size_t parsed_bytes = sizeof(Dot11MgtHeader);

// Control estricto de límites para evitar desbordamiento de búfer (Buffer Overflow)
while (radiotap_len + parsed_bytes + 2 <= pkthdr->caplen) {
    uint8_t element_id = ie_start[0];
    uint8_t element_len = ie_start[1];

    // Verificar que los datos declarados por el elemento estén dentro del paquete capturado
    if (radiotap_len + parsed_bytes + 2 + element_len > pkthdr->caplen) {
        break; // Elemento malformado o incompleto
    }

    // Element ID 0 es el SSID
    if (element_id == 0) {
        if (element_len > 0 && element_len <= 32) {
            std::string ssid(reinterpret_cast<const char*>(ie_start + 2), element_len);
            std::cout << "[*] SSID Solicitado: " << ssid << std::endl;

            // Filtrado lógico perimetral
            if (ssid.find("Totalplay-") != std::string::npos) {
                std::cout << "[!] Alerta: Cliente buscando red perimetral específica: " << ssid << std::endl;
                // Aquí se activaría conceptualmente la lógica de respuesta (Beacon/Probe Response)
            }
        } else {
            std::cout << "[*] Broadcast / Hidden SSID (Sondeo pasivo)" << std::endl;
        }
        break; // El SSID suele ser el primer elemento; podemos salir del bucle.
    }

    // Avanzar al siguiente elemento TLV
    size_t step = 2 + element_len;
    ie_start += step;
    parsed_bytes += step;
}
