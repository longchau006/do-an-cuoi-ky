# -*- coding: utf-8 -*-
import os

SIGNATURES = {
    "jpg": {"header": b'\xFF\xD8\xFF', "footer": b'\xFF\xD9'},
    "png": {"header": b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', "footer": b'\x49\x45\x4E\x44\xAE\x42\x60\x82'}
}

def find_images_in_vol(vol_path, output_dir):

    os.makedirs(output_dir, exist_ok=True)
    
    with open(vol_path, 'rb') as vol_file:
        data = vol_file.read() 
        
        for img_type, sig in SIGNATURES.items():
            header = sig["header"]
            footer = sig["footer"]
            start_idx = 0 

            while start_idx < len(data):

                header_idx = data.find(header, start_idx)
                if header_idx == -1:
                    break 

                footer_idx = data.find(footer, header_idx)
                if footer_idx != -1:
                    img_data = data[header_idx:footer_idx + len(footer)]
                    output_file = os.path.join(output_dir, f"recovered_{header_idx}.{img_type}")
                    with open(output_file, 'wb') as out:
                        out.write(img_data)
                    print(f"Da phuc hoi {output_file}")
                    start_idx = footer_idx + len(footer)
                else:
                    print(f"Footer khong tim thay, trich xuat du lieu tu {header_idx}")
                    img_data = data[header_idx:header_idx + 1024 * 100] 
                    output_file = os.path.join(output_dir, f"partial_{header_idx}.{img_type}")
                    with open(output_file, 'wb') as out:
                        out.write(img_data)
                    start_idx = header_idx + len(header)

if __name__ == "__main__":
    vol_path = "Volume001.vol.001" 
    output_dir = "D:\\Recovered" 
    find_images_in_vol(vol_path, output_dir)
    print("Complete")

