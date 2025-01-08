import pandas as pd
import argparse

# Python script to merge multiple csv files based on common fields. Primarily used for combining splunk results exports into a single file. 

def merge_csv_files(input_files, output_file):
    # Read first CSV file
    combined_df = pd.read_csv(input_files[0])

    # Merge with next CSV file(s)
    for file in input_files[1:]:
        df = pd.read_csv(file)
        combined_df = pd.merge(combined_df, df, how="outer", on=list(set(combined_df.columns) & set(df.columns)))

    # Sort by '_time' column (if exists)
    if '_time' in combined_df.columns:
        combined_df.sort_values(by="_time", inplace=True)

    # Write the combined dataframe to the output file
    combined_df.to_csv(output_file, index=False)

def main():
    parser = argparse.ArgumentParser(description="Combine multiple CSV files by matching columns and sort by the '_time' column.")
    parser.add_argument("input_files", nargs='+', help="Paths to the input CSV files.")
    parser.add_argument("output_file", help="Path to the output CSV file.")

    args = parser.parse_args()

    if len(args.input_files) < 2:
        parser.error("At least two input CSV files are required.")

    merge_csv_files(args.input_files, args.output_file)

if __name__ == "__main__":
    main()
