from PIL import Image, ImageDraw

def create_icon():
    # Create a 256x256 image with a dark background
    img = Image.new('RGB', (256, 256), color = (43, 43, 43))
    
    d = ImageDraw.Draw(img)
    # Draw a green shield-like shape
    d.polygon([(128, 20), (220, 60), (200, 200), (128, 240), (56, 200), (36, 60)], fill=(76, 175, 80), outline=(255, 255, 255))
    
    # Draw text "CG"
    # d.text((100,100), "CG", fill=(255,255,255)) # Default font might be too small, skip text for simplicity
    
    img.save('assets/icon.png')
    print("Icon created successfully.")

if __name__ == "__main__":
    create_icon()
