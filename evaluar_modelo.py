#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import pandas as pd
import numpy as np

# Componentes de modelado
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE

# Visualización
import matplotlib.pyplot as plt
import seaborn as sns

# Rutas
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset_estructurado_extendido.csv")
CONFUSION_MATRIX_PATH = os.path.join(BASE_DIR, "matriz_confusion.png")

def main():
    print("====================================================================")
    print("INICIANDO FASE 3: PIPELINE MODELO HIBRIDO (SUPERVISADO + NO SUPERVISADO)")
    print("====================================================================")

    # --- 1. PREPROCESAMIENTO Y BALANCEO (SMOTE) ---
    print("Cargando dataset estructurado extendido...")
    try:
        if not os.path.exists(DATASET_PATH):
            raise FileNotFoundError(f"No se encuentra el archivo en la ruta especificada: {DATASET_PATH}")
        df = pd.read_csv(DATASET_PATH, sep=None, engine='python')
        print(f"Dataset cargado con éxito. Instancias: {df.shape[0]}, Columnas: {df.shape[1]}")
    except Exception as e:
        print(f"Error crítico al cargar el dataset: {e}")
        sys.exit(1)

    X = df.drop(columns=['Clase_Objetivo'])
    y = df['Clase_Objetivo']
    feature_names = X.columns.tolist()

    # Split Train/Test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"División de datos completada (80% Train / 20% Test).")
    print(f"  * Muestras de Entrenamiento: {X_train.shape[0]}")
    print(f"  * Muestras de Prueba: {X_test.shape[0]}")

    # Escalamiento estándar
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    X_train_scaled_df = pd.DataFrame(X_train_scaled, columns=feature_names, index=X_train.index)
    X_test_scaled_df = pd.DataFrame(X_test_scaled, columns=feature_names, index=X_test.index)

    # Balanceo con SMOTE (solo en Train)
    print("\nAplicando SMOTE en el conjunto de entrenamiento para balancear clases...")
    counts_before = y_train.value_counts()
    print("Distribución original en el entrenamiento:")
    class_labels = {0: "Normal (0)", 1: "FuerzaBruta (1)", 2: "SQLi (2)"}
    for val, count in counts_before.items():
        print(f"  * {class_labels[val]}: {count} muestras")
        
    smote = SMOTE(random_state=42)
    X_train_bal, y_train_bal = smote.fit_resample(X_train_scaled_df, y_train)
    
    counts_after = y_train_bal.value_counts()
    print("Distribución después de SMOTE en el entrenamiento:")
    for val, count in counts_after.items():
        print(f"  * {class_labels[val]}: {count} muestras")

    # --- 2. SELECCIÓN DE CARACTERÍSTICAS (IMPUREZA DE GINI) ---
    print("\nEjecutando Selección de Características mediante importancia de Bosque Aleatorio...")
    forest_selector = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    forest_selector.fit(X_train_bal, y_train_bal)
    
    importances = forest_selector.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    top_n = 10
    selected_features = [feature_names[i] for i in indices[:top_n]]
    selected_importances = importances[indices[:top_n]]
    
    print(f"Top {top_n} características seleccionadas por relevancia (Gini):")
    for r, (name, imp) in enumerate(zip(selected_features, selected_importances), 1):
        print(f"  {r}. {name:<30} | Peso de Importancia: {imp:.6f}")

    X_train_filtered = X_train_bal[selected_features]
    X_test_filtered = X_test_scaled_df[selected_features]

    # --- 3. CONSTRUCCIÓN DEL ENFOQUE HÍBRIDO ---
    print("\nEntrenando la Rama Supervisada (Random Forest)...")
    rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_classifier.fit(X_train_filtered, y_train_bal)

    print("Entrenando la Rama No Supervisada (Isolation Forest)...")
    X_train_normal_only = X_train_scaled_df.loc[y_train == 0, selected_features]
    print(f"  * Muestras normales de entrenamiento utilizadas para modelar normalidad: {X_train_normal_only.shape[0]}")
    
    if_detector = IsolationForest(contamination='auto', random_state=42, n_jobs=-1)
    if_detector.fit(X_train_normal_only)

    # Motor de decisión híbrido
    print("\nEjecutando Inferencia Híbrida sobre el conjunto de prueba independiente...")
    rf_preds = rf_classifier.predict(X_test_filtered)
    if_preds = if_detector.predict(X_test_filtered)

    y_pred_hybrid = []
    corrections_count = 0
    for rf_pred, if_pred in zip(rf_preds, if_preds):
        if rf_pred in [1, 2]:
            y_pred_hybrid.append(rf_pred)
        elif rf_pred == 0 and if_pred == -1:
            y_pred_hybrid.append(3)  # Clase 3: Amenaza Desconocida
            corrections_count += 1
        else:
            y_pred_hybrid.append(0)

    y_pred_hybrid = np.array(y_pred_hybrid)

    # --- 4. EVALUACIÓN DE RESULTADOS ---
    print("\n====================================================================")
    print("REPORTE DE EVALUACION: RAMA SUPERVISADA (RANDOM FOREST) AISLADA")
    print("====================================================================")
    print(classification_report(y_test, rf_preds, target_names=["Normal (0)", "FuerzaBruta (1)", "SQLi (2)"]))

    # Matriz de Confusión base
    cm_rf = confusion_matrix(y_test, rf_preds)
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm_rf, annot=True, fmt='d', cmap='Blues',
        xticklabels=["Normal (0)", "FuerzaBruta (1)", "SQLi (2)"],
        yticklabels=["Normal (0)", "FuerzaBruta (1)", "SQLi (2)"]
    )
    plt.title('Matriz de Confusión - Random Forest (Rama Supervisada Aislada)', fontsize=13, pad=15)
    plt.ylabel('Clase Real (Ground Truth)', fontsize=11)
    plt.xlabel('Clase Predicha por RF', fontsize=11)
    plt.tight_layout()
    plt.savefig(CONFUSION_MATRIX_PATH, dpi=300)
    print(f"Gráfico de la matriz de confusión base guardado en: {CONFUSION_MATRIX_PATH}")
    
    print("\n====================================================================")
    print("ANALISIS DEL APORTE DEL MOTOR NO SUPERVISADO (ISOLATION FOREST)")
    print("====================================================================")
    print(f"El Isolation Forest 'corrigio' al Random Forest un total de: {corrections_count} veces.")
    
    # Distribución de predicciones híbridas
    print("\nDistribución final de las predicciones del Motor Híbrido:")
    unique, counts = np.unique(y_pred_hybrid, return_counts=True)
    hybrid_class_names = {0: "0 (Normal / Benigno)", 1: "1 (Ataque_FuerzaBruta)", 2: "2 (Ataque_SQLi)", 3: "3 (Amenaza Desconocida / Anomalia)"}
    for val, count in zip(unique, counts):
        percentage = (count / len(y_pred_hybrid)) * 100
        print(f"  * Clase {hybrid_class_names[val]}: {count} predicciones ({percentage:.2f}%)")
    print("====================================================================")

if __name__ == "__main__":
    main()
