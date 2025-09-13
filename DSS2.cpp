#include <iostream>
#include <vector>
#include <bitset>
#include <random>
#include <functional>
#include <cmath>
#include <algorithm>
#include <string>
#include <sstream>
#include <memory>

using namespace std;

// Configuracion - N numero de funciones y llaves 
const int NUM_FUNCIONES = 6; 

// Funcion para verificar si un numero es primo
bool esPrimo(uint64_t n) {
    if (n <= 1) return false; //1 o cualquier numero inferior a 1 no es primo
    if (n <= 3) return true; // 2 y 3 son primos
    if (n % 2 == 0 || n % 3 == 0) return false; //Si el numero es divisible por 2 o por 3 no es primo
    
    for (uint64_t i = 5; i * i <= n; i += 6) { //Si un numero no es primo entonces existe un numero i inferior a su raiz cuadrada que lo divida
        if (n % i == 0 || n % (i + 2) == 0) //Probamos si el numero i o si el numero i+2 dividen nuestro numero n 
            return false;
    }
    return true;
}

// Funcion scrambled para crear la llave embrion
uint64_t funcionScrambled(uint64_t S, uint64_t P) {
    uint64_t resultado = S;
    resultado = resultado ^ (P << 17); //Se cambian los bits del resultado si estos coinciden con los bits despues de haber puesto 16 ceros (^ = XOR)
    resultado = (resultado >> 13) | (resultado << (64 - 13)); //Se desplazan los bits del resultado a la derecha 13 veces haciendolos rotar
    resultado = resultado ^ (P >> 5);
    resultado = resultado ^ (P << 29);
    resultado = (resultado << 7) | (resultado >> (64 - 7));
    resultado = resultado ^ (P >> 11);
    resultado = resultado ^ (P << 19);
    resultado = (resultado >> 23) | (resultado << (64 - 23));
    resultado = resultado ^ (P >> 3);
    return resultado;
}

// Funcion de generacion que usa la llave embrion y Q
uint64_t funcionGeneracion(uint64_t embrion, uint64_t Q) {
    uint64_t llave = embrion;
    llave = llave ^ Q;
    llave = (llave << 19) | (llave >> (64 - 19));
    llave = llave + Q;
    llave = llave ^ (Q << 31);
    llave = (llave >> 11) | (llave << (64 - 11));
    llave = llave * (Q | 1); //Se realiza otro XOR con Q pero con su bit mas significativo cambiado a 1
    llave = llave | 0x1;
    return llave;
}

// Funcion de mutación que modifica S usando Q
uint64_t funcionMutacion(uint64_t S, uint64_t Q) {
    uint64_t nuevoS = S;
    nuevoS = nuevoS ^ (Q << 17);
    nuevoS = (nuevoS << 13) | (nuevoS >> (64 - 13));
    nuevoS = nuevoS + Q;
    nuevoS = nuevoS ^ (Q >> 7);
    nuevoS = (nuevoS >> 19) | (nuevoS << (64 - 19));
    nuevoS = nuevoS * (Q | 1);
    if (nuevoS == 0) nuevoS = Q ^ 0xFFFFFFFFFFFFFFFF; //Si el valor de S es cero se modifica al XOR de Q usando el numero representado por 64 bits con valor 1
    return nuevoS;
}

// Generar N llaves diferentes 
vector<uint64_t> generarLlaves(uint64_t P, uint64_t Q, uint64_t S, int num_llaves) {
    vector<uint64_t> llaves;
    uint64_t semilla = S;
    
    for (int i = 0; i < num_llaves; i++) {
        uint64_t embrion = funcionScrambled(semilla, P);
        uint64_t llave = funcionGeneracion(embrion, Q);
        semilla = funcionMutacion(semilla, Q);
        llaves.push_back(llave);
    }
    return llaves;
}

// ================== FUNCIONES REVERSIBLES ==================

// Tipo para parametros de funciones
using ParametrosFuncion = vector<uint64_t>;

// Interfaz para funciones reversibles
class FuncionReversible {
public:
    virtual pair<uint64_t, ParametrosFuncion> cifrar(uint64_t dato, uint64_t llave) = 0;
    virtual uint64_t descifrar(uint64_t datoCifrado, uint64_t llave, const ParametrosFuncion& parametros) = 0;
    virtual ~FuncionReversible() {}
};

// Implementaciones concretas de funciones
class Funcion1 : public FuncionReversible {
public:
    pair<uint64_t, ParametrosFuncion> cifrar(uint64_t dato, uint64_t llave) override {
        uint8_t rotaciones = (llave % 63) + 1; //Se dice cuantos bits se va mover la llave a la izquierda (un numero entre 1 y 63)
        uint64_t temp = (dato << rotaciones) | (dato >> (64 - rotaciones)); //Se realiza la rotacion
        return {temp ^ llave, {static_cast<uint64_t>(rotaciones)}}; //Se realiza la operacion XOR usando la llave guardando el numero de rotaciones realizadas
    }
    
    uint64_t descifrar(uint64_t datoCifrado, uint64_t llave, const ParametrosFuncion& parametros) override { //Proceso contrario
        uint8_t rotaciones = static_cast<uint8_t>(parametros[0]);
        uint64_t temp = datoCifrado ^ llave;
        return (temp >> rotaciones) | (temp << (64 - rotaciones));
    }
};

class Funcion2 : public FuncionReversible {
public:
    pair<uint64_t, ParametrosFuncion> cifrar(uint64_t dato, uint64_t llave) override {
        uint64_t mask = (llave >> 32) | (llave << 32); //Se rota la llave por 32 bits
        uint64_t temp = dato ^ llave; //Se realiza la operacion XOR sobre el numero usando llave
        temp = (temp << 17) | (temp >> (64 - 17)); //Se rota el numero 17 veces
        temp = temp ^ mask; //Se realiza la operacion XOR sobre el numero rotado
        return {temp, {mask}};
    }
    
    uint64_t descifrar(uint64_t datoCifrado, uint64_t llave, const ParametrosFuncion& parametros) override { //Proceso contrario
        uint64_t mask = parametros[0];
        uint64_t temp = datoCifrado ^ mask;
        temp = (temp >> 17) | (temp << (64 - 17));
        return temp ^ llave;
    }
};

class Funcion3 : public FuncionReversible {
public:
    pair<uint64_t, ParametrosFuncion> cifrar(uint64_t dato, uint64_t llave) override {
        uint64_t parte1 = (llave & 0xFFFFFFFF); //Se ponen igual a cero los 32 bits mas significativos
        uint64_t parte2 = (llave >> 32); //Se mueven todos los bits 32 posiciones a la izquierda agregando ceros
        uint64_t temp = dato;
        
        temp = temp ^ parte1; 
        temp = (temp << 13) | (temp >> (64 - 13));
        temp = temp + parte2;
        temp = temp ^ (parte1 << 16);
        
        return {temp, {parte2}};
    }
    
    uint64_t descifrar(uint64_t datoCifrado, uint64_t llave, const ParametrosFuncion& parametros) override { //Proceso contrario
        uint64_t parte1 = (llave & 0xFFFFFFFF);
        uint64_t parte2 = parametros[0];
        uint64_t temp = datoCifrado;
        
        temp = temp ^ (parte1 << 16);
        temp = temp - parte2;
        temp = (temp >> 13) | (temp << (64 - 13));
        return temp ^ parte1;
    }
};

class Funcion4 : public FuncionReversible {
public:
    pair<uint64_t, ParametrosFuncion> cifrar(uint64_t dato, uint64_t llave) override {
        uint8_t rot1 = (llave % 31) + 1; //Se decide cuantas rotaciones van a a realizarse en un primer lugar
        uint8_t rot2 = ((llave >> 8) % 31) + 1; //Se modifica la llave moviendo sus bits luego se decide cuantas rotaciones se realizaran en un segundo lugar
        
        uint64_t temp = dato;
        temp = temp ^ llave;
        temp = (temp << rot1) | (temp >> (64 - rot1));
        temp = temp ^ (llave >> 16);
        temp = (temp >> rot2) | (temp << (64 - rot2));
        temp = temp ^ (llave << 16);
        
        return {temp, {static_cast<uint64_t>(rot1), static_cast<uint64_t>(rot2)}};
    }
    
    uint64_t descifrar(uint64_t datoCifrado, uint64_t llave, const ParametrosFuncion& parametros) override {//Proceso contrario
        uint8_t rot1 = static_cast<uint8_t>(parametros[0]);
        uint8_t rot2 = static_cast<uint8_t>(parametros[1]);
        uint64_t temp = datoCifrado;
        
        temp = temp ^ (llave << 16);
        temp = (temp << rot2) | (temp >> (64 - rot2));
        temp = temp ^ (llave >> 16);
        temp = (temp >> rot1) | (temp << (64 - rot1));
        return temp ^ llave;
    }
};

// Factory para crear funciones
vector<unique_ptr<FuncionReversible>> crearFunciones(int n) {
    vector<unique_ptr<FuncionReversible>> funciones;
    
    // Mapeo de tipos de funciones disponibles
    vector<function<unique_ptr<FuncionReversible>()>> fabricas = {
        []() { return make_unique<Funcion1>(); },
        []() { return make_unique<Funcion2>(); },
        []() { return make_unique<Funcion3>(); },
        []() { return make_unique<Funcion4>(); }
    };
    
    for (int i = 0; i < n; i++) {
        int tipo = i % fabricas.size();
        funciones.push_back(fabricas[tipo]());
    }
    
    return funciones;
}

// ================== SISTEMA DE CIFRADO CON 4 BITS ==================

struct ResultadoCifrado {
    uint64_t mensajeCifrado;
    vector<int> ordenFunciones;
    vector<ParametrosFuncion> parametros;
    uint8_t bitsOrden; // Exactamente 4 bits
};

// Funcion para determinar el orden basado en los 4 bits del PSN
vector<int> determinarOrdenDesde4Bits(uint8_t bits, int n) {
    vector<int> orden(n);
    
    // Los 4 bits se interpretan de la siguiente manera:
    // bit0-1: índice de la primera Funcion (0-3)
    // bit2-3: patrón para permutar las funciones restantes
    
    int primeraFuncion = (bits * n) >> 4;
    
    orden[0] = primeraFuncion;
    
    // Crear lista de funciones restantes
    vector<int> restantes;
    for (int i = 0; i < n; i++) {
        if (i != primeraFuncion) {
            restantes.push_back(i);
        }
    }
    
    // Usar los bits 2-3 para determinar el orden de las restantes
    int patron = (bits >> 2) & 0x3;
    
    switch (patron) {
        case 0: // Orden original
            for (int i = 0; i < restantes.size(); i++) {
                orden[i + 1] = restantes[i];
            }
            break;
        case 1: // Orden inverso
            for (int i = 0; i < restantes.size(); i++) {
                orden[i + 1] = restantes[restantes.size() - 1 - i];
            }
            break;
        case 2: // Rotación izquierda
            if (restantes.size() >= 2) {
                orden[1] = restantes[1];
                if (restantes.size() >= 3) orden[2] = restantes[2];
                if (restantes.size() >= 4) orden[3] = restantes[0];
            }
            break;
        case 3: // Rotación derecha
            if (restantes.size() >= 3) orden[1] = restantes[2];
            if (restantes.size() >= 2) orden[2] = restantes[0];
            if (restantes.size() >= 4) orden[3] = restantes[1];
            break;
    }
    
    return orden;
}

// Funcion para generar 4 bits aleatorios
uint8_t generar4BitsOrden() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 15);
    return dis(gen);
}

// Funcion para cifrar un bloque con orden determinado por 4 bits
ResultadoCifrado cifrarBloque(uint64_t bloque, const vector<uint64_t>& llaves, 
                             const vector<unique_ptr<FuncionReversible>>& funciones,
                             uint8_t bitsOrden) {
    ResultadoCifrado resultado;
    resultado.mensajeCifrado = bloque;
    resultado.parametros.resize(funciones.size());
    resultado.bitsOrden = bitsOrden;
    
    // Determinar orden desde los 4 bits
    resultado.ordenFunciones = determinarOrdenDesde4Bits(bitsOrden, funciones.size());
    
    // Aplicar funciones en el orden determinado
    for (int funcId : resultado.ordenFunciones) {
        auto& funcion = funciones[funcId];
        uint64_t llave = llaves[funcId];
        
        auto [cifrado, params] = funcion->cifrar(resultado.mensajeCifrado, llave);
        resultado.mensajeCifrado = cifrado;
        resultado.parametros[funcId] = params;
    }
    
    return resultado;
}

// Funcion para descifrar un bloque
uint64_t descifrarBloque(uint64_t bloqueCifrado, const vector<uint64_t>& llaves, 
                        const vector<unique_ptr<FuncionReversible>>& funciones,
                        const vector<int>& ordenFunciones, 
                        const vector<ParametrosFuncion>& parametros) {
    uint64_t mensaje = bloqueCifrado;
    
    // Aplicar funciones en orden inverso
    for (int i = ordenFunciones.size() - 1; i >= 0; i--) {
        int funcId = ordenFunciones[i];
        auto& funcion = funciones[funcId];
        uint64_t llave = llaves[funcId];
        
        mensaje = funcion->descifrar(mensaje, llave, parametros[funcId]);
    }
    
    return mensaje;
}

// Funcion para convertir string a uint64_t
uint64_t stringToUint64(const string& str) {
    uint64_t result = 0;
    size_t len = min(str.length(), size_t(8));
    for (size_t i = 0; i < len; i++) {
        result = (result << 8) | static_cast<uint8_t>(str[i]);
    }
    return result;
}

// Funcion para convertir uint64_t a string
string uint64ToString(uint64_t value) {
    string result;
    for (int i = 7; i >= 0; i--) {
        char c = (value >> (i * 8)) & 0xFF;
        if (c != 0) result += c;
    }
    return result;
}

// Funcion para dividir mensaje largo en bloques de 64 bits
vector<uint64_t> dividirMensaje(const string& mensaje) {
    vector<uint64_t> bloques;
    for (size_t i = 0; i < mensaje.length(); i += 8) {
        string bloqueStr = mensaje.substr(i, 8);
        // Rellenar con zeros si es necesario
        while (bloqueStr.length() < 8) {
            bloqueStr += '\0';
        }
        bloques.push_back(stringToUint64(bloqueStr));
    }
    return bloques;
}

// Funcion para unir bloques en mensaje completo
string unirMensaje(const vector<uint64_t>& bloques) {
    string resultado;
    for (uint64_t bloque : bloques) {
        string bloqueStr = uint64ToString(bloque);
        // Eliminar caracteres nulos al final
        while (!bloqueStr.empty() && bloqueStr.back() == '\0') {
            bloqueStr.pop_back();
        }
        resultado += bloqueStr;
    }
    return resultado;
}

// Funcion principal
int main() {
    try {
        cout << "=== SISTEMA DE CIFRADO CON " << NUM_FUNCIONES << " FUNCIONES Y " << NUM_FUNCIONES << " LLAVES ===" << endl;
        
        // parametros iniciales
        uint64_t P = 18446744073709551557ULL;
        uint64_t Q = 18446744073709551533ULL;
        uint64_t S = 12345678901234567890ULL;
        
        // Generar llaves (mismo numero que funciones)
        vector<uint64_t> llaves = generarLlaves(P, Q, S, NUM_FUNCIONES);
        
        cout << "\nLlaves generadas:" << endl;
        for (int i = 0; i < NUM_FUNCIONES; i++) {
            cout << "Llave " << i+1 << ": 0x" << hex << llaves[i] << dec << endl;
        }
        
        // Crear funciones
        auto funciones = crearFunciones(NUM_FUNCIONES);
        
        // Leer mensaje del usuario
        string mensajeStr;
        cout << "\nIngrese el mensaje a cifrar: ";
        getline(cin, mensajeStr);
        
        if (mensajeStr.empty()) {
            mensajeStr = "Este es un mensaje de prueba más largo para demostrar el cifrado de múltiples bloques";
        }
        
        // Dividir mensaje en bloques de 64 bits
        vector<uint64_t> bloques = dividirMensaje(mensajeStr);
        cout << "Mensaje dividido en " << bloques.size() << " bloques de 64 bits" << endl;
        
        // Generar 4 bits de orden (mismos para todos los bloques)
        uint8_t bitsOrden = generar4BitsOrden();
        cout << "4 bits de orden: " << bitset<4>(bitsOrden) << endl;
        
        // Cifrar todos los bloques
        cout << "\n=== CIFRADO ===" << endl;
        vector<ResultadoCifrado> resultados;
        for (size_t i = 0; i < bloques.size(); i++) {
            cout << "Cifrando bloque " << i+1 << "..." << endl;
            ResultadoCifrado resultado = cifrarBloque(bloques[i], llaves, funciones, bitsOrden);
            resultados.push_back(resultado);
            cout << "  Bloque cifrado: 0x" << hex << resultado.mensajeCifrado << dec << endl;
        }
        
        // Mostrar orden de funciones
        cout << "Orden de funciones: ";
        for (int funcId : resultados[0].ordenFunciones) {
            cout << funcId + 1 << " ";
        }
        cout << endl;
        
        // Descifrar todos los bloques
        cout << "\n=== DESCIFRADO ===" << endl;
        vector<uint64_t> bloquesDescifrados;
        for (size_t i = 0; i < resultados.size(); i++) {
            cout << "Descifrando bloque " << i+1 << "..." << endl;
            uint64_t bloqueDescifrado = descifrarBloque(
                resultados[i].mensajeCifrado, llaves, funciones,
                resultados[i].ordenFunciones, resultados[i].parametros
            );
            bloquesDescifrados.push_back(bloqueDescifrado);
            cout << "  Bloque descifrado: 0x" << hex << bloqueDescifrado << dec << endl;
        }
        
        // Unir mensaje descifrado
        string mensajeDescifradoStr = unirMensaje(bloquesDescifrados);
        
        cout << "\nMensaje original: '" << mensajeStr << "'" << endl;
        cout << "Mensaje descifrado: '" << mensajeDescifradoStr << "'" << endl;
        
        // Verificación
        cout << "\n=== VERIFICACIÓN ===" << endl;
        if (mensajeStr == mensajeDescifradoStr) {
            cout << "✓ Cifrado/descifrado exitoso para todos los bloques!" << endl;
        } else {
            cout << "✗ Error en el cifrado/descifrado" << endl;
            cout << "Longitud original: " << mensajeStr.length() << endl;
            cout << "Longitud descifrado: " << mensajeDescifradoStr.length() << endl;
        }
        
        // Mostrar información
        cout << "\n=== INFORMACIÓN ===" << endl;
        cout << "numero de funciones: " << NUM_FUNCIONES << endl;
        cout << "numero de llaves: " << llaves.size() << endl;
        cout << "numero de bloques: " << bloques.size() << endl;
        cout << "4 bits de orden: " << bitset<4>(bitsOrden) << endl;
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}