import streamlit as st
import pandas as pd
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------- USTAWIENIA STRONY ------------- #
st.set_page_config(
    page_title="Eksporter opisów produktów z Akeneo", 
    page_icon="📦", 
    layout="wide"
)

# ------------- AKENEO API ------------- #
def _akeneo_root():
    """Zwraca bazowy URL Akeneo bez /api/rest/v1"""
    base = st.secrets["AKENEO_BASE_URL"].rstrip("/")
    if base.endswith("/api/rest/v1"):
        return base[:-len("/api/rest/v1")]
    return base

def akeneo_get_token():
    """Pobiera token autoryzacyjny z Akeneo"""
    token_url = _akeneo_root() + "/api/oauth/v1/token"
    auth = (st.secrets["AKENEO_CLIENT_ID"], st.secrets["AKENEO_SECRET"])
    data = {
        "grant_type": "password",
        "username": st.secrets["AKENEO_USERNAME"],
        "password": st.secrets["AKENEO_PASSWORD"],
    }
    try:
        r = requests.post(token_url, auth=auth, data=data, timeout=30)
        r.raise_for_status()
        return r.json()["access_token"]
    except Exception as e:
        raise RuntimeError(f"Błąd podczas uzyskiwania tokenu: {e}")

def akeneo_get_product(sku, token):
    """
    Pobiera dane produktu z Akeneo PIM dla danego SKU.
    Zwraca słownik z danymi produktu lub None w przypadku błędu.
    """
    url = _akeneo_root() + f"/api/rest/v1/products/{sku}"
    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 404:
            return None  # Produkt nie istnieje
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"Błąd podczas pobierania SKU {sku}: {e}")
        return None

def extract_product_info(product_data, sku):
    """
    Ekstraktuje nazwę i opis z danych produktu.
    Obsługuje różne konfiguracje atrybutów (scopable/localizable).
    """
    if not product_data:
        return {
            'sku': sku,
            'nazwa': 'PRODUKT NIE ISTNIEJE',
            'opis': 'PRODUKT NIE ISTNIEJE'
        }
    
    values = product_data.get('values', {})
    
    # Pobieranie nazwy produktu (może być w różnych formatach)
    nazwa = ""
    if 'name' in values:
        name_values = values['name']
        if name_values:
            # Bierzemy pierwszą dostępną wartość
            nazwa = name_values[0].get('data', '')
    
    # Jeśli nie ma 'name', spróbuj innych atrybutów
    if not nazwa and 'product_name' in values:
        product_name_values = values['product_name']
        if product_name_values:
            nazwa = product_name_values[0].get('data', '')
    
    # Pobieranie opisu
    opis = ""
    if 'description' in values:
        desc_values = values['description']
        if desc_values:
            # Bierzemy pierwszą dostępną wartość
            opis = desc_values[0].get('data', '')
    
    return {
        'sku': sku,
        'nazwa': nazwa if nazwa else 'Brak nazwy',
        'opis': opis if opis else 'Brak opisu'
    }

def process_single_sku(sku, token):
    """Przetwarza pojedynczy SKU i zwraca informacje o produkcie"""
    product_data = akeneo_get_product(sku.strip(), token)
    return extract_product_info(product_data, sku.strip())

# ------------- INICJALIZACJA SESSION STATE ------------- #
if 'results_df' not in st.session_state:
    st.session_state.results_df = None

# ------------- INTERFEJS UŻYTKOWNIKA ------------- #
st.title("📦 Eksporter opisów produktów z Akeneo PIM")
st.markdown("Pobierz nazwy i opisy produktów z systemu PIM dla podanych kodów SKU.")

# Sprawdzenie czy są skonfigurowane secrets
try:
    missing_secrets = []
    required_secrets = ["AKENEO_BASE_URL", "AKENEO_CLIENT_ID", "AKENEO_SECRET", 
                       "AKENEO_USERNAME", "AKENEO_PASSWORD"]
    
    for secret in required_secrets:
        if secret not in st.secrets:
            missing_secrets.append(secret)
    
    if missing_secrets:
        st.error(f"❌ Brakujące dane konfiguracyjne w secrets: {', '.join(missing_secrets)}")
        st.info("Upewnij się, że plik .streamlit/secrets.toml zawiera wszystkie wymagane dane dostępowe do Akeneo.")
        st.stop()
except Exception as e:
    st.error(f"❌ Błąd konfiguracji: {e}")
    st.stop()

st.markdown("---")

# Sekcja wprowadzania danych
st.header("📝 Wprowadź kody SKU")

col1, col2 = st.columns([2, 1])

with col1:
    input_method = st.radio(
        "Wybierz sposób wprowadzania SKU:",
        ["Wklej listę", "Wczytaj z pliku CSV"],
        horizontal=True
    )
    
    sku_list = []
    
    if input_method == "Wklej listę":
        sku_input = st.text_area(
            "Kody SKU (jeden na linię)",
            height=200,
            placeholder="SKU-001\nSKU-002\nSKU-003",
            help="Wprowadź kody SKU, każdy w nowej linii"
        )
        if sku_input:
            sku_list = [sku.strip() for sku in sku_input.splitlines() if sku.strip()]
    
    else:  # Wczytaj z pliku CSV
        uploaded_file = st.file_uploader(
            "Wybierz plik CSV z kodami SKU",
            type=['csv'],
            help="Plik powinien zawierać kolumnę z kodami SKU"
        )
        
        if uploaded_file is not None:
            try:
                df_upload = pd.read_csv(uploaded_file)
                st.write("**Podgląd pliku:**")
                st.dataframe(df_upload.head(), use_container_width=True)
                
                # Wybór kolumny z SKU
                column_name = st.selectbox(
                    "Wybierz kolumnę zawierającą kody SKU:",
                    df_upload.columns.tolist()
                )
                
                if column_name:
                    sku_list = df_upload[column_name].dropna().astype(str).str.strip().tolist()
                    sku_list = [sku for sku in sku_list if sku]
                    
            except Exception as e:
                st.error(f"❌ Błąd podczas wczytywania pliku: {e}")

with col2:
    st.info(f"**Liczba SKU:** {len(sku_list)}")
    
    if sku_list:
        with st.expander("📋 Podgląd SKU"):
            st.write(sku_list[:20])
            if len(sku_list) > 20:
                st.write(f"... i {len(sku_list) - 20} więcej")

# Przyciski akcji
st.markdown("---")
col_btn1, col_btn2, col_btn3 = st.columns([2, 1, 1])

with col_btn1:
    fetch_button = st.button(
        "🚀 Pobierz opisy z Akeneo",
        type="primary",
        use_container_width=True,
        disabled=len(sku_list) == 0
    )

with col_btn2:
    if st.button("🔄 Wyczyść wyniki", use_container_width=True):
        st.session_state.results_df = None
        st.rerun()

with col_btn3:
    max_workers = st.number_input(
        "Równoległe wątki",
        min_value=1,
        max_value=10,
        value=5,
        help="Liczba równoległych zapytań do API"
    )

# Pobieranie danych
if fetch_button and sku_list:
    st.markdown("---")
    st.subheader("⏳ Przetwarzanie...")
    
    try:
        # Pobierz token
        with st.spinner("Uwierzytelnianie z Akeneo..."):
            token = akeneo_get_token()
        
        st.success("✅ Uwierzytelniono pomyślnie!")
        
        # Pobierz dane produktów
        results = []
        progress_bar = st.progress(0, text="Rozpoczynam pobieranie danych...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sku = {
                executor.submit(process_single_sku, sku, token): sku 
                for sku in sku_list
            }
            
            for i, future in enumerate(as_completed(future_to_sku)):
                result = future.result()
                results.append(result)
                progress = (i + 1) / len(sku_list)
                progress_bar.progress(
                    progress, 
                    text=f"Pobrano {i+1}/{len(sku_list)} produktów..."
                )
        
        # Sortuj wyniki w kolejności podanych SKU
        sku_to_result = {r['sku']: r for r in results}
        sorted_results = [sku_to_result[sku] for sku in sku_list if sku in sku_to_result]
        
        # Utwórz DataFrame
        st.session_state.results_df = pd.DataFrame(sorted_results)
        
        progress_bar.progress(1.0, text="Zakończono!")
        st.success(f"✅ Pobrano dane dla {len(sorted_results)} produktów!")
        
    except Exception as e:
        st.error(f"❌ Błąd podczas pobierania danych: {e}")

# Wyświetlanie wyników
if st.session_state.results_df is not None:
    st.markdown("---")
    st.header("📊 Wyniki")
    
    df = st.session_state.results_df
    
    # Statystyki
    col_stat1, col_stat2, col_stat3 = st.columns(3)
    with col_stat1:
        st.metric("Liczba produktów", len(df))
    with col_stat2:
        missing_count = len(df[df['nazwa'] == 'PRODUKT NIE ISTNIEJE'])
        st.metric("Nieznalezione", missing_count)
    with col_stat3:
        no_desc_count = len(df[(df['opis'] == 'Brak opisu') & (df['nazwa'] != 'PRODUKT NIE ISTNIEJE')])
        st.metric("Bez opisu", no_desc_count)
    
    st.markdown("---")
    
    # Tabela z wynikami
    st.subheader("📋 Tabela wyników")
    
    # Filtrowanie
    show_filter = st.checkbox("🔍 Pokaż filtry", value=False)
    
    if show_filter:
        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            filter_option = st.selectbox(
                "Filtruj wyniki:",
                ["Wszystkie", "Tylko ze znalezionymi produktami", "Tylko nieznalezione", "Tylko bez opisu"]
            )
        
        if filter_option == "Tylko ze znalezionymi produktami":
            df_display = df[df['nazwa'] != 'PRODUKT NIE ISTNIEJE']
        elif filter_option == "Tylko nieznalezione":
            df_display = df[df['nazwa'] == 'PRODUKT NIE ISTNIEJE']
        elif filter_option == "Tylko bez opisu":
            df_display = df[(df['opis'] == 'Brak opisu') & (df['nazwa'] != 'PRODUKT NIE ISTNIEJE')]
        else:
            df_display = df
    else:
        df_display = df
    
    # Wyświetl tabelę
    st.dataframe(
        df_display,
        use_container_width=True,
        height=400,
        column_config={
            "sku": st.column_config.TextColumn("SKU", width="small"),
            "nazwa": st.column_config.TextColumn("Nazwa produktu", width="medium"),
            "opis": st.column_config.TextColumn("Opis", width="large"),
        }
    )
    
    # Eksport do CSV
    st.markdown("---")
    st.subheader("💾 Eksport danych")
    
    col_export1, col_export2 = st.columns(2)
    
    with col_export1:
        # Eksport wszystkich danych
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Pobierz wszystkie wyniki (CSV)",
            data=csv,
            file_name='akeneo_produkty_wszystkie.csv',
            mime='text/csv',
            use_container_width=True
        )
    
    with col_export2:
        # Eksport tylko znalezionych produktów
        df_found = df[df['nazwa'] != 'PRODUKT NIE ISTNIEJE']
        if len(df_found) > 0:
            csv_found = df_found.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Pobierz tylko znalezione (CSV)",
                data=csv_found,
                file_name='akeneo_produkty_znalezione.csv',
                mime='text/csv',
                use_container_width=True
            )
        else:
            st.info("Brak znalezionych produktów do eksportu")

# ------------- STOPKA ------------- #
st.markdown("---")
st.markdown("🔧 **Eksporter opisów produktów z Akeneo PIM** | Wersja 1.0")
