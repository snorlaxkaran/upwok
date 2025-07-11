import {
  v2 as cloudinary,
  UploadApiErrorResponse,
  UploadApiResponse,
} from 'cloudinary';

export function uploads(
  file: string,
  public_id?: string,
  overwrite?: boolean,
  invalidate?: boolean
): Promise<UploadApiErrorResponse | UploadApiResponse | undefined> {
  return new Promise((resolve) => {
    cloudinary.uploader.upload(
      file,
      {
        public_id,
        overwrite,
        invalidate,
        resource_type: 'auto',
      },
      (
        error: UploadApiErrorResponse | undefined,
        result: UploadApiResponse | undefined
      ) => {
        if (error) resolve(error);
        resolve(result);
      }
    );
  });
}

export function videoUpload(
  file: string,
  public_id?: string,
  overwrite?: boolean,
  invalidate?: boolean
): Promise<UploadApiErrorResponse | UploadApiResponse | undefined> {
  return new Promise((resolve) => {
    cloudinary.uploader.upload(
      file,
      {
        public_id,
        overwrite,
        invalidate,
        chunk_size: 50000,
        resource_type: 'video',
      },
      (
        error: UploadApiErrorResponse | undefined,
        result: UploadApiResponse | undefined
      ) => {
        if (error) resolve(error);
        resolve(result);
      }
    );
  });
}
