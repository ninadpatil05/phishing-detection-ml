"""
Data Loader Module for Phishing Detection Dataset

This module handles loading, preprocessing, and splitting the phishing email dataset.
It performs data cleaning, label encoding, and creates train/validation/test splits.
"""

import os
import pandas as pd
from sklearn.model_selection import train_test_split


def load_raw_data(filepath):
    """
    Load the raw phishing dataset from CSV file.
    
    Args:
        filepath (str): Path to the raw CSV file
        
    Returns:
        pd.DataFrame: Raw dataset with original column names
        
    Raises:
        FileNotFoundError: If the CSV file doesn't exist
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Dataset not found at {filepath}")
    
    print(f"Loading data from {filepath}...")
    df = pd.read_csv(filepath)
    print(f"Loaded {len(df)} rows from raw dataset")
    return df


def preprocess_data(df):
    """
    Preprocess the dataset by renaming columns, encoding labels, and cleaning data.
    
    Steps:
    1. Rename columns to standardized names
    2. Convert categorical labels to binary (Phishing Email -> 1, Safe Email -> 0)
    3. Remove rows with empty or NaN email text
    
    Args:
        df (pd.DataFrame): Raw dataset with original column names
        
    Returns:
        pd.DataFrame: Preprocessed dataset with clean data and binary labels
    """
    print("\nPreprocessing data...")
    
    # Step 1: Rename columns to standard names
    df = df.rename(columns={
        "Email Text": "email_text",
        "Email Type": "label"
    })
    print("✓ Renamed columns to standard format")
    
    # Step 2: Convert labels to binary
    label_mapping = {
        "Phishing Email": 1,
        "Safe Email": 0
    }
    df["label"] = df["label"].map(label_mapping)
    print("✓ Converted labels to binary (Phishing=1, Safe=0)")
    
    # Step 3: Remove rows with empty or NaN email_text
    initial_rows = len(df)
    df = df.dropna(subset=["email_text"])
    df = df[df["email_text"].str.strip() != ""]
    rows_removed = initial_rows - len(df)
    print(f"✓ Removed {rows_removed} rows with empty/NaN email text")
    
    return df


def print_class_balance(df, dataset_name="Dataset"):
    """
    Print class distribution statistics for the dataset.
    
    Args:
        df (pd.DataFrame): Dataset with 'label' column
        dataset_name (str): Name of the dataset for display purposes
    """
    total = len(df)
    phishing_count = (df["label"] == 1).sum()
    safe_count = (df["label"] == 0).sum()
    phishing_pct = (phishing_count / total) * 100
    safe_pct = (safe_count / total) * 100
    
    print(f"\n{dataset_name} Class Balance:")
    print(f"  Total rows:        {total}")
    print(f"  Phishing (1):      {phishing_count} ({phishing_pct:.2f}%)")
    print(f"  Safe (0):          {safe_count} ({safe_pct:.2f}%)")


def split_data(df, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_state=42):
    """
    Split dataset into train, validation, and test sets.
    
    Uses stratified splitting to maintain class balance across all splits.
    
    Args:
        df (pd.DataFrame): Preprocessed dataset
        train_ratio (float): Proportion for training set (default: 0.70)
        val_ratio (float): Proportion for validation set (default: 0.15)
        test_ratio (float): Proportion for test set (default: 0.15)
        random_state (int): Random seed for reproducibility (default: 42)
        
    Returns:
        tuple: (train_df, val_df, test_df) DataFrames
    """
    print(f"\nSplitting data (Train: {train_ratio*100}%, Val: {val_ratio*100}%, Test: {test_ratio*100}%)...")
    
    # First split: separate test set
    train_val_df, test_df = train_test_split(
        df,
        test_size=test_ratio,
        random_state=random_state,
        stratify=df["label"]
    )
    
    # Second split: separate train and validation
    val_ratio_adjusted = val_ratio / (train_ratio + val_ratio)
    train_df, val_df = train_test_split(
        train_val_df,
        test_size=val_ratio_adjusted,
        random_state=random_state,
        stratify=train_val_df["label"]
    )
    
    print(f"✓ Split complete:")
    print(f"  Train set: {len(train_df)} rows")
    print(f"  Val set:   {len(val_df)} rows")
    print(f"  Test set:  {len(test_df)} rows")
    
    return train_df, val_df, test_df


def save_splits(train_df, val_df, test_df, output_dir):
    """
    Save train, validation, and test splits to CSV files.
    
    Args:
        train_df (pd.DataFrame): Training dataset
        val_df (pd.DataFrame): Validation dataset
        test_df (pd.DataFrame): Test dataset
        output_dir (str): Directory to save the processed CSV files
    """
    print(f"\nSaving splits to {output_dir}...")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Save each split
    train_df.to_csv(os.path.join(output_dir, "train.csv"), index=False)
    val_df.to_csv(os.path.join(output_dir, "val.csv"), index=False)
    test_df.to_csv(os.path.join(output_dir, "test.csv"), index=False)
    
    print("✓ Saved train.csv")
    print("✓ Saved val.csv")
    print("✓ Saved test.csv")


def print_summary_report(train_df, val_df, test_df):
    """
    Print a comprehensive summary report showing class balance in all splits.
    
    Args:
        train_df (pd.DataFrame): Training dataset
        val_df (pd.DataFrame): Validation dataset
        test_df (pd.DataFrame): Test dataset
    """
    print("\n" + "=" * 60)
    print("SUMMARY REPORT: Dataset Split & Class Balance")
    print("=" * 60)
    
    print_class_balance(train_df, "Training Set")
    print_class_balance(val_df, "Validation Set")
    print_class_balance(test_df, "Test Set")
    
    print("\n" + "=" * 60)
    print("Data loading and preprocessing complete!")
    print("=" * 60)


def main():
    """
    Main execution function that orchestrates the entire data loading pipeline.
    
    Pipeline steps:
    1. Load raw data from CSV
    2. Preprocess and clean data
    3. Check and display class balance
    4. Split into train/val/test sets
    5. Save processed splits
    6. Print summary report
    """
    # Define file paths
    raw_data_path = "data/raw/Phishing_Email.csv"
    processed_data_dir = "data/processed"
    
    # Step 1: Load raw data
    df = load_raw_data(raw_data_path)
    
    # Step 2: Preprocess data
    df = preprocess_data(df)
    
    # Step 3: Check class balance
    print_class_balance(df, "Full Dataset")
    
    # Step 4: Split data
    train_df, val_df, test_df = split_data(
        df,
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
        random_state=42
    )
    
    # Step 5: Save splits
    save_splits(train_df, val_df, test_df, processed_data_dir)
    
    # Step 6: Print summary report
    print_summary_report(train_df, val_df, test_df)


if __name__ == "__main__":
    main()
