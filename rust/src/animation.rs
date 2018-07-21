use std::collections::HashMap;

use ggez::Context;
use serde_yaml::Value;
use warmy;

use crate::error::{err_from, CompatError};

#[derive(Debug, Clone)]
pub enum ImageType {
    NonSolid,
    Collidee,
}

#[derive(Debug, Clone)]
pub struct Image {
    pub sheet: String,
    pub image: usize,
    pub x: i32,
    pub y: i32,
    pub image_type: ImageType,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub images: Vec<Image>,
}

#[derive(Debug)]
pub struct Sprite {
    pub animations: HashMap<String, Vec<Frame>>,
}

impl warmy::Load<Context> for Sprite {
    type Key = warmy::LogicalKey;
    type Error = CompatError;

    fn load(
        key: Self::Key,
        store: &mut warmy::Storage<ggez::Context>,
        ctx: &mut ggez::Context,
    ) -> Result<warmy::Loaded<Self>, Self::Error> {
        let file = ctx.filesystem.open(key.as_str()).map_err(err_from)?;
        let yaml: Value = serde_yaml::from_reader(file).map_err(err_from)?;

        let mut animations: HashMap<String, Vec<Frame>> = HashMap::new();

        for (key, animation) in yaml.as_mapping().unwrap().iter() {
            let frame_values = animation["frames"].as_sequence().unwrap();
            let mut frames = Vec::new();

            for image_values in frame_values {
                let mut frame = Frame { images: Vec::new() };
                for image in image_values.as_sequence().unwrap() {
                    frame.images.push(Image {
                        sheet: image["sheet"].as_str().unwrap().to_string(),
                        image: image["image"].as_u64().unwrap() as usize,
                        x: image["x"].as_i64().unwrap() as i32,
                        y: image["y"].as_i64().unwrap() as i32,
                        image_type: match image["type"].as_str().unwrap() {
                            "NON_SOLID" => ImageType::NonSolid,
                            "COLLIDEE" => ImageType::Collidee,
                            _ => panic!("unknown image type"),
                        },
                    })
                }
                frames.push(frame);
            }
            animations.insert(key.as_str().unwrap().to_string(), frames);
        }

        Ok(warmy::Loaded::from(Sprite {
            animations: animations,
        }))
    }
}
