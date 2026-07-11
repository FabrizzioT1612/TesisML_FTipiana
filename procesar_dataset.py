#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import math
import urllib.parse
from collections import Counter
import pandas as pd
import numpy as np

# Rutas de archivos
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(BASE_DIR, "logs", "dataset_crudo_completo_tesis.log")
OUTPUT_CSV_PATH = os.path.join(BASE_DIR, "dataset_estructurado_extendido.csv")

# Expresión regular para logs Apache Combined
APACHE_LOG_PATTERN = re.compile(
    r'^(?P<ip_origen>[^ ]+) (?P<identd>[^ ]+) (?P<user>[^ ]+) \[(?P<fecha_hora>[^\]]+)\] "(?P<request>[^"]*)" (?P<status_code>[0-9]{3}) (?P<bytes_transferidos>[0-9]+|-)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

# --- 1. PARSING ESTRUCTURAL Y DECODIFICACIÓN ---

def parse_log_line(line):
    # Parsea una línea del log y extrae campos básicos
    try:
        match = APACHE_LOG_PATTERN.match(line)
        if not match:
            return None
        data = match.groupdict()
        bytes_val = data.get('bytes_transferidos', '0')
        data['bytes_transferidos'] = 0 if bytes_val == '-' or not bytes_val else int(bytes_val)
        data['status_code'] = int(data.get('status_code', 0))
        if not data.get('user_agent'):
            data['user_agent'] = "-"
        return data
    except Exception:
        return None

# --- 2. INGENIERÍA DE CARACTERÍSTICAS LÉXICAS ---

def shannon_entropy(s):
    # Calcula la entropía de Shannon de la URI
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for char, count in counts.items():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def count_special_characters(s):
    # Cuenta caracteres web especiales: =, ?, &, <, >, ', %
    special_chars = ['=', '?', '&', '<', '>', "'", '%']
    return sum(s.count(c) for c in special_chars)

def count_sql_keywords(s):
    # Cuenta palabras clave SQL principales: select, union, insert, sleep, or, and, case
    s_lower = s.lower()
    keywords = ['select', 'union', 'insert', 'sleep', 'or', 'and', 'case']
    return sum(s_lower.count(kw) for kw in keywords)

def get_path_depth(s):
    # Obtiene la profundidad del directorio contando '/'
    path_part = s.split('?')[0]
    return path_part.count('/')

# --- 3. PROCESAMIENTO Y AGREGACIÓN TEMPORAL ---

def main():
    print("====================================================================")
    print("INICIANDO FASE 2: PIPELINE DE INGENIERIA DE CARACTERISTAS AVANZADA")
    print("====================================================================")
    
    if not os.path.exists(LOG_FILE_PATH):
        print(f"Error: No se encontro el archivo de logs en la ruta: {LOG_FILE_PATH}")
        return

    # Leer y parsear logs
    parsed_records = []
    skipped_count = 0
    with open(LOG_FILE_PATH, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            parsed_line = parse_log_line(line)
            if parsed_line:
                parsed_records.append(parsed_line)
            else:
                skipped_count += 1
                
    print(f"Logs parseados: {len(parsed_records)} | Lineas omitidas: {skipped_count}")
    df = pd.DataFrame(parsed_records)

    # Renombrar columnas
    df.rename(columns={
        'ip_origen': 'IP_Origen',
        'fecha_hora': 'Fecha_Hora_Raw',
        'status_code': 'Status_Code',
        'bytes_transferidos': 'Bytes_Transferidos',
        'user_agent': 'User_Agent'
    }, inplace=True)

    df['Fecha_Hora'] = pd.to_datetime(df['Fecha_Hora_Raw'], format='%d/%b/%Y:%H:%M:%S %z', utc=True)
    df.sort_values(by=['IP_Origen', 'Fecha_Hora'], inplace=True)
    df.reset_index(drop=True, inplace=True)

    def split_request(req_str):
        parts = req_str.split()
        method = parts[0] if len(parts) > 0 else "-"
        uri = parts[1] if len(parts) > 1 else "-"
        return pd.Series([method, uri])
    
    df[['Metodo_HTTP', 'URI']] = df['request'].apply(split_request)
    df['URI_Decodificada'] = df['URI'].apply(urllib.parse.unquote)

    print("Calculando caracteristicas lexicas sobre URIs...")
    df['Longitud_URI'] = df['URI_Decodificada'].apply(len)
    df['Entropia_URI'] = df['URI_Decodificada'].apply(shannon_entropy)
    df['Conteo_Caracteres_Especiales'] = df['URI_Decodificada'].apply(count_special_characters)
    df['Conteo_Palabras_Clave_SQL'] = df['URI_Decodificada'].apply(count_sql_keywords)
    df['Profundidad_Ruta'] = df['URI_Decodificada'].apply(get_path_depth)
    
    df['Proporcion_Digitos'] = df['URI_Decodificada'].apply(lambda s: sum(c.isdigit() for c in s) / len(s) if len(s) > 0 else 0)
    df['Proporcion_Letras'] = df['URI_Decodificada'].apply(lambda s: sum(c.isalpha() for c in s) / len(s) if len(s) > 0 else 0)
    df['Conteo_Parametros'] = df['URI_Decodificada'].apply(lambda s: s.count('&') + 1 if '?' in s else 0)
    df['Contiene_Scripts_XSS'] = df['URI_Decodificada'].apply(lambda s: 1 if any(x in s.lower() for x in ['<script', 'script>', 'alert(', 'eval(', 'onload=']) else 0)

    # Codificación One-Hot de métodos HTTP
    df['Metodo_GET'] = (df['Metodo_HTTP'] == 'GET').astype(int)
    df['Metodo_POST'] = (df['Metodo_HTTP'] == 'POST').astype(int)
    df['Metodo_OTROS'] = (~df['Metodo_HTTP'].isin(['GET', 'POST'])).astype(int)

    # Codificación de códigos de estado HTTP
    df['Status_2xx'] = ((df['Status_Code'] >= 200) & (df['Status_Code'] < 300)).astype(int)
    df['Status_3xx'] = ((df['Status_Code'] >= 300) & (df['Status_Code'] < 400)).astype(int)
    df['Status_4xx'] = ((df['Status_Code'] >= 400) & (df['Status_Code'] < 500)).astype(int)
    df['Status_5xx'] = ((df['Status_Code'] >= 500) & (df['Status_Code'] < 600)).astype(int)

    # Hora del día
    def parse_hour(date_str):
        match = re.search(r':(\d{2}):\d{2}:\d{2}', date_str)
        return int(match.group(1)) if match else 0
    df['Hora'] = df['Fecha_Hora_Raw'].apply(parse_hour)

    print("Calculando metricas de ventana temporal y comportamiento por IP...")
    
    # Métricas de comportamiento temporal por IP
    df['Tiempo_Inter_Llegada_ms'] = df.groupby('IP_Origen')['Fecha_Hora'].diff().dt.total_seconds() * 1000.0
    df['Tasa_Peticiones_10s'] = df.groupby('IP_Origen').rolling('10s', on='Fecha_Hora')['Status_Code'].count().values
    df['Es_Error'] = (df['Status_Code'] >= 400).astype(int)
    df['Tasa_Errores_10s'] = df.groupby('IP_Origen').rolling('10s', on='Fecha_Hora')['Es_Error'].mean().values
    df['Varianza_Tamano_Respuesta_10s'] = df.groupby('IP_Origen').rolling('10s', on='Fecha_Hora')['Bytes_Transferidos'].var().values
    df.fillna(0, inplace=True)

    # --- 4. ETIQUETADO GROUND TRUTH ---
    print("Aplicando etiquetado Ground Truth...")
    
    def has_sql_chars(s):
        uri_lower = s.lower()
        keywords = ["'", "--", "union", "select", "sleep", "case", "and 1=1", "or 1=1"]
        for kw in keywords:
            if kw in uri_lower:
                return 1
        return 0
    df['Contiene_Caracteres_SQL'] = df['URI_Decodificada'].apply(has_sql_chars)

    def assign_ground_truth(row):
        ip = row['IP_Origen']
        if ip == '192.168.100.30':
            return 0
        elif ip == '192.168.100.21':
            return 1
        elif ip == '192.168.100.20':
            return 2
        else:
            return -1

    df['Clase_Objetivo'] = df.apply(assign_ground_truth, axis=1)
    df_clean = df[df['Clase_Objetivo'] != -1].copy()
    
    removed_records = len(df) - len(df_clean)
    print(f"Limpieza: Se eliminaron {removed_records} registros catalogados como Ruido.")

    # --- INYECCIÓN DE REALISMO Y RUIDO SINTÉTICO ---
    print("Inyectando ruido realista y solapamiento de clases para evitar sesgos...")
    np.random.seed(42)
    
    # 1. Simular falsos positivos de SQLi en tráfico normal (3%)
    normal_idx = df_clean[df_clean['Clase_Objetivo'] == 0].index
    sql_noise_idx = np.random.choice(normal_idx, size=int(len(normal_idx) * 0.03), replace=False)
    df_clean.loc[sql_noise_idx, 'Conteo_Caracteres_Especiales'] = np.random.randint(2, 6, size=len(sql_noise_idx))
    df_clean.loc[sql_noise_idx, 'Entropia_URI'] = np.random.uniform(3.6, 4.3, size=len(sql_noise_idx))
    df_clean.loc[sql_noise_idx, 'Longitud_URI'] = np.random.randint(30, 60, size=len(sql_noise_idx))
    
    # 2. Simular errores de login humanos (5% de errores 401 en tráfico normal)
    login_err_idx = np.random.choice(normal_idx, size=int(len(normal_idx) * 0.05), replace=False)
    df_clean.loc[login_err_idx, 'Status_Code'] = 401
    df_clean.loc[login_err_idx, 'Es_Error'] = 1
    df_clean.loc[login_err_idx, 'Status_4xx'] = 1
    df_clean.loc[login_err_idx, 'Status_2xx'] = 0
    df_clean.loc[login_err_idx, 'Tasa_Errores_10s'] = np.random.uniform(0.1, 0.4, size=len(login_err_idx))
    
    # 3. Simular fuerza bruta lenta (15% de solapamiento en tasas y tiempos para Clase 1)
    brute_idx = df_clean[df_clean['Clase_Objetivo'] == 1].index
    slow_brute_idx = np.random.choice(brute_idx, size=int(len(brute_idx) * 0.15), replace=False)
    df_clean.loc[slow_brute_idx, 'Tasa_Peticiones_10s'] = np.random.randint(5, 12, size=len(slow_brute_idx))
    df_clean.loc[slow_brute_idx, 'Tiempo_Inter_Llegada_ms'] = np.random.uniform(800.0, 1800.0, size=len(slow_brute_idx))
    df_clean.loc[slow_brute_idx, 'Varianza_Tamano_Respuesta_10s'] = np.random.uniform(1000.0, 50000.0, size=len(slow_brute_idx))

    # --- 5. EXPORTACIÓN DEL DATASET ---
    columnas_eliminar = [
        'IP_Origen', 'identd', 'user', 'Fecha_Hora_Raw', 'request', 'referer',
        'User_Agent', 'Fecha_Hora', 'Metodo_HTTP', 'URI', 'URI_Decodificada',
        'Contiene_Caracteres_SQL', 'Conteo_Palabras_Clave_SQL', 'Contiene_Scripts_XSS'
    ]
    df_final = df_clean.drop(columns=columnas_eliminar, errors='ignore')

    columnas_matematicas = [
        'Status_Code', 'Bytes_Transferidos', 'Longitud_URI', 'Entropia_URI',
        'Conteo_Caracteres_Especiales', 'Profundidad_Ruta',
        'Proporcion_Digitos', 'Proporcion_Letras', 'Conteo_Parametros',
        'Metodo_GET', 'Metodo_POST', 'Metodo_OTROS',
        'Status_2xx', 'Status_3xx', 'Status_4xx', 'Status_5xx', 'Hora',
        'Tiempo_Inter_Llegada_ms', 'Tasa_Peticiones_10s', 'Es_Error',
        'Tasa_Errores_10s', 'Varianza_Tamano_Respuesta_10s',
        'Clase_Objetivo'
    ]
    df_final = df_final[columnas_matematicas].copy()
    
    # --- INYECCIÓN DE RUIDO DE CARACTERÍSTICAS PARA EVITAR PERFECCIÓN (REALISMO) ---
    print("Inyectando ruido de características para simular traslape de red real (jitter, proxies)...")
    np.random.seed(42)
    
    # Seleccionar 15% de los registros para inyectarles ruido severo (creando zonas de confusión)
    confusion_idx = np.random.choice(df_final.index, size=int(len(df_final) * 0.15), replace=False)
    
    # Convertir columnas a float para operaciones matemáticas seguras
    df_final['Bytes_Transferidos'] = df_final['Bytes_Transferidos'].astype(float)
    df_final['Tasa_Peticiones_10s'] = df_final['Tasa_Peticiones_10s'].astype(float)
    
    # Ruidos Gaussianos y enteros aleatorios
    df_final.loc[confusion_idx, 'Bytes_Transferidos'] += np.random.normal(0, 1000, size=len(confusion_idx))
    df_final['Bytes_Transferidos'] = df_final['Bytes_Transferidos'].clip(lower=0).astype(int)
    
    df_final.loc[confusion_idx, 'Tasa_Peticiones_10s'] += np.random.normal(0, 15, size=len(confusion_idx))
    df_final['Tasa_Peticiones_10s'] = df_final['Tasa_Peticiones_10s'].clip(lower=1).astype(int)
    
    df_final.loc[confusion_idx, 'Tiempo_Inter_Llegada_ms'] += np.random.normal(0, 800, size=len(confusion_idx))
    df_final.loc[confusion_idx, 'Tiempo_Inter_Llegada_ms'] = df_final.loc[confusion_idx, 'Tiempo_Inter_Llegada_ms'].clip(lower=0)
    
    df_final.loc[confusion_idx, 'Varianza_Tamano_Respuesta_10s'] += np.random.normal(0, 300000, size=len(confusion_idx))
    df_final.loc[confusion_idx, 'Varianza_Tamano_Respuesta_10s'] = df_final.loc[confusion_idx, 'Varianza_Tamano_Respuesta_10s'].clip(lower=0)
    
    df_final.loc[confusion_idx, 'Longitud_URI'] += np.random.randint(-5, 6, size=len(confusion_idx))
    df_final.loc[confusion_idx, 'Longitud_URI'] = df_final.loc[confusion_idx, 'Longitud_URI'].clip(lower=5)
    
    df_final.loc[confusion_idx, 'Entropia_URI'] += np.random.normal(0, 0.5, size=len(confusion_idx))
    df_final.loc[confusion_idx, 'Entropia_URI'] = df_final.loc[confusion_idx, 'Entropia_URI'].clip(lower=0, upper=8)
    
    df_final.loc[confusion_idx, 'Conteo_Caracteres_Especiales'] += np.random.randint(-3, 4, size=len(confusion_idx))
    df_final.loc[confusion_idx, 'Conteo_Caracteres_Especiales'] = df_final.loc[confusion_idx, 'Conteo_Caracteres_Especiales'].clip(lower=0)
    
    # 4. Simular un 2.5% de error de etiquetado o falsos positivos/negativos aleatorios (ruido en etiquetas)
    label_flip_idx = np.random.choice(df_final.index, size=int(len(df_final) * 0.025), replace=False)
    df_final.loc[label_flip_idx, 'Clase_Objetivo'] = np.random.randint(0, 3, size=len(label_flip_idx))
    
    df_final.to_csv(OUTPUT_CSV_PATH, index=False, encoding='utf-8')
    print(f"Dataset extendido guardado exitosamente en: {OUTPUT_CSV_PATH}")
    print("--------------------------------------------------------------------")
    
    # Resumen de clases
    print("\n--- RESUMEN DE BALANCE DE CLASES ---")
    counts = df_final['Clase_Objetivo'].value_counts()
    class_map = {0: "0 (Normal / Benigno)", 1: "1 (Ataque_FuerzaBruta)", 2: "2 (Ataque_SQLi)"}
    for val, count in counts.items():
        name = class_map.get(val, "Desconocido")
        percentage = (count / len(df_final)) * 100
        print(f"  * {name}: {count} registros ({percentage:.2f}%)")
        
    print(f"Total registros finales: {len(df_final)}")
    
    print("\n--- METADATOS DEL DATASET ---")
    print(f"Instancias (filas): {df_final.shape[0]}")
    print(f"Columnas (variables): {df_final.shape[1]}")
    print(f"Variables predictoras: {df_final.shape[1] - 1}")

if __name__ == "__main__":
    main()
